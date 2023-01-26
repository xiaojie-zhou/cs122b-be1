package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.Role;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class IDMJwtManager
{
    private final JWTManager jwtManager;

    @Autowired
    public IDMJwtManager(IDMServiceConfig serviceConfig)
    {
        this.jwtManager =
            new JWTManager.Builder()
                .keyFileName(serviceConfig.keyFileName())
                .accessTokenExpire(serviceConfig.accessTokenExpire())
                .maxRefreshTokenLifeTime(serviceConfig.maxRefreshTokenLifeTime())
                .refreshTokenExpire(serviceConfig.refreshTokenExpire())
                .build();
    }

    private SignedJWT buildAndSignJWT(JWTClaimsSet claimsSet)
        throws JOSEException
    {
        JWSHeader header = new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
                .keyID(jwtManager.getEcKey().getKeyID())
                .type(JWTManager.JWS_TYPE)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwtManager.getSigner());

        return signedJWT;
    }

//    private void verifyJWT(SignedJWT jwt)
//        throws JOSEException, BadJOSEException
//    {
//
//
//    }

    public String buildAccessToken(User user) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .expirationTime(Date.from(Instant.now().plus(jwtManager.getAccessTokenExpire())))
                .issueTime(Date.from(Instant.now()))
                .claim(JWTManager.CLAIM_ID, user.getId())
                .claim(JWTManager.CLAIM_ROLES, user.getRoles())
                .build();

        return this.buildAndSignJWT(claimsSet).serialize();

    }

    public void verifyAccessToken(String jws)
            throws IllegalStateException, ParseException, JOSEException, BadJOSEException,RuntimeException
    {
        SignedJWT rebuiltSignedJwt = SignedJWT.parse(jws);

        rebuiltSignedJwt.verify(jwtManager.getVerifier());
        jwtManager.getJwtProcessor().process(rebuiltSignedJwt, null);

        // Do logic to check if expired manually
        if(Instant.now().isAfter(rebuiltSignedJwt.getJWTClaimsSet().getExpirationTime().toInstant())){
            throw new RuntimeException("Expired");
        }
    }

    public RefreshToken buildRefreshToken(User user)
    {
        return new RefreshToken()
                .setToken(UUID.randomUUID().toString())
                .setUserId(user.getId())
                .setTokenStatus(TokenStatus.ACTIVE)
                .setExpireTime(Instant.now().plus(jwtManager.getRefreshTokenExpire()))
                .setMaxLifeTime(Instant.now().plus(jwtManager.getMaxRefreshTokenLifeTime()));
    }

//    public boolean hasExpired(RefreshToken refreshToken)
//    {
//        return false;
//    }
//
//    public boolean needsRefresh(RefreshToken refreshToken)
//    {
//        return false;
//    }

    public RefreshToken updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {
        refreshToken.setExpireTime(Instant.now().plus(jwtManager.getRefreshTokenExpire()));
        return refreshToken;
    }

    private UUID generateUUID()
    {
        return UUID.randomUUID();
    }
}
