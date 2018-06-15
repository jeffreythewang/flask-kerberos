import kerberos

from flask import Response
from flask import _request_ctx_stack as stack
from flask import make_response
from flask import request
from functools import partial, wraps
from inspect import getargspec
from socket import gethostname
from os import environ

_SERVICE_NAME = None


def init_kerberos(app, service='HTTP', hostname=gethostname()):
    '''
    Configure the GSSAPI service name, and validate the presence of the
    appropriate principal in the kerberos keytab.

    :param app: a flask application
    :type app: flask.Flask
    :param service: GSSAPI service name
    :type service: str
    :param hostname: hostname the service runs under
    :type hostname: str
    '''
    global _SERVICE_NAME
    _SERVICE_NAME = "%s@%s" % (service, hostname)

    if 'KRB5_KTNAME' not in environ:
        app.logger.warn("Kerberos: set KRB5_KTNAME to your keytab file")
    else:
        try:
            principal = kerberos.getServerPrincipalDetails(service, hostname)
        except kerberos.KrbError as exc:
            app.logger.warn("Kerberos: %s" % exc.message[0])
        else:
            app.logger.info("Kerberos: server is %s" % principal)


def _unauthorized():
    '''
    Indicate that authentication is required
    '''
    return Response('Unauthorized', 401, {'WWW-Authenticate': 'Negotiate'})


def _forbidden():
    '''
    Indicate a complete authentication failure
    '''
    return Response('Forbidden', 403)


def _gssapi_authenticate(token, delegate=False):
    '''
    Performs GSSAPI Negotiate Authentication

    On success also stashes the server response token for mutual authentication
    at the top of request context with the name kerberos_token, along with the
    authenticated user principal with the name kerberos_user.

    @param token: GSSAPI Authentication Token
    @param delegate: whether the context is to be used for accepting delegated credentials
    @type token: str
    @returns gssapi return code or None on failure
    @rtype: int or None
    '''
    state = None
    ctx = stack.top
    try:
        service_name = _SERVICE_NAME
        if delegate:
            service_name = "DELEGATE"
        rc, state = kerberos.authGSSServerInit(service_name)
        if rc != kerberos.AUTH_GSS_COMPLETE:
            return None
        rc = kerberos.authGSSServerStep(state, token)
        if rc == kerberos.AUTH_GSS_COMPLETE:
            ctx.kerberos_context = state
            ctx.kerberos_token = kerberos.authGSSServerResponse(state)
            ctx.kerberos_user = kerberos.authGSSServerUserName(state)
            return rc
        elif rc == kerberos.AUTH_GSS_CONTINUE:
            return kerberos.AUTH_GSS_CONTINUE
        else:
            return None
    except kerberos.GSSError:
        return None
    finally:
        if state:
            kerberos.authGSSServerClean(state)


def requires_authentication(function=None, delegate=False):
    '''
    Require that the wrapped view function only be called by users
    authenticated with Kerberos. The view function will have the authenticated
    users principal passed to it as its first argument.

    :param function: flask view function
    :param delegate: whether the context is to be used for accepting delegated credentials
    :type function: function
    :returns: decorated function
    :rtype: function
    '''
    if function is None:
        return partial(requires_authentication, delegate=delegate)
    @wraps(function)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization")
        if header:
            ctx = stack.top
            token = ''.join(header.split()[1:])
            rc = _gssapi_authenticate(token, delegate)
            if rc == kerberos.AUTH_GSS_COMPLETE:
                args_list = (ctx.kerberos_user, ctx.kerberos_context)
                num_args = len(getargspec(function).args)
                args = args_list[:num_args]
                response = function(*args, **kwargs)
                response = make_response(response)
                if ctx.kerberos_token is not None:
                    response.headers['WWW-Authenticate'] = ' '.join(['negotiate',
                                                                     ctx.kerberos_token])
                return response
            elif rc != kerberos.AUTH_GSS_CONTINUE:
                return _forbidden()
        return _unauthorized()
    return decorated
