const jsrsasign = require('jsrsasign');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto')


function generateDPoPHeader(url, method, accessToken, publicKey, privateKey) {
    accessToken = accessToken.split('Bearer ')[1];
    const jti = uuidv4();

    const accessTokenHash = crypto
        .createHash('sha256')
        .update(accessToken)
        .digest('base64url');

    const payload = {
        htm: method,
        htu: url.split('?')[0],
        iat: Math.floor(Date.now() / 1000),
        jti: jti,
        ath: accessTokenHash
    };

    const publicKeyJwk = jsrsasign.KEYUTIL.getJWK(publicKey)
    const header = {
        typ: 'dpop+jwt',
        alg: 'ES512',
        jwk: publicKeyJwk
    };

    return jsrsasign.KJUR.jws.JWS.sign("ES512", header, payload, privateKey);
}


module.exports.requestHooks = [
    (context) => {
        if (context.request.hasHeader('DPoP')) {
            let dpop;
            try {
                const pubKey = context.request.getHeader('PublicKey') || context.request.getEnvironmentVariable('DPoPPublicKey');
                const privKey = context.request.getHeader('PrivateKey') || context.request.getEnvironmentVariable('DPoPPrivateKey');
                //console.log('pubKey', pubKey);
                //console.log(context.request.getEnvironmentVariable('DPoPPublicKey'));
                //console.log(atob(context.request.getEnvironmentVariable('DPoPPublicKey')));
                dpop = generateDPoPHeader(context.request.getUrl(), 'GET', context.request.getHeader('Authorization'), atob(pubKey), atob(privKey));
                //console.log('dpop', dpop);
            } catch (e) {
                context.app.alert("Error", "Generating DPoP Header failed.");
            }
            context.request.removeHeader('PublicKey');
            context.request.removeHeader('PrivateKey');
            context.request.setHeader('DPoP', dpop);
        }
    },
];

