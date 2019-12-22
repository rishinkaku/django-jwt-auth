=======
JWTAuth
=======

JWTAuth is a Django app to have a ready-to-use authentication system. Security is the most important thing it can provide.

Detailed documentation is in the "docs" directory.

Quick start
-----------

1. Add "jwt_auth" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'jwt_auth',
    ]
    
2. Add "jwt_auth.middleware.JWTAuthMiddleware" to your MIDDLEWARE setting like this, under the built-in "AuthenticationMiddleware"::
    
    MIDDLEWARE = [
        ...
        'jwt_auth.middleware.JWTAuthMiddleware',
    ]
    
3. Add "jwt_auth.authenticate.JWTBackend" to your AUTHENTICATION_BACKENDS settings like this::

    AUTHENTICATION_BACKENDS = [
        ...
        'jwt_auth.authenticate.JWTBackend',
    ]
    
4. Set "JWT_AUTH_PRIVATE_KEY" and "JWT_AUTH_PUBLIC_KEY" which has to be a pem formatted rsa keypair (create it like this::

    ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
    # Don't add passphrase
    openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
    cat jwtRS256.key
    cat jwtRS256.key.pub

5. Include the jwt_auth URLconf in your project urls.py like this::

    path('auth/',include('jwt_auth.urls')),
    
6. Run `python manage.py migrate` to create the needed models.

7. Enjoy your new auth system!