package com.github.klefstad_teaching.cs122b.idm.rest;

import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.model.authenticate.AuthModel;
import com.github.klefstad_teaching.cs122b.idm.model.authenticate.AuthRequest;
import com.github.klefstad_teaching.cs122b.idm.model.login.LoginModel;
import com.github.klefstad_teaching.cs122b.idm.model.login.LoginRequest;
import com.github.klefstad_teaching.cs122b.idm.model.refresh.RefreshModel;
import com.github.klefstad_teaching.cs122b.idm.model.refresh.RefreshRequest;
import com.github.klefstad_teaching.cs122b.idm.model.register.RegisterModel;
import com.github.klefstad_teaching.cs122b.idm.model.register.RegisterRequest;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import com.github.klefstad_teaching.cs122b.idm.util.Validate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


import java.text.ParseException;
import java.time.Instant;
import java.util.regex.Pattern;

@RestController
public class IDMController
{
    private final IDMAuthenticationManager authManager;
    private final IDMJwtManager            jwtManager;
    private final Validate                 validate;

    @Autowired
    public IDMController(IDMAuthenticationManager authManager,
                         IDMJwtManager jwtManager,
                         Validate validate)
    {
        this.authManager = authManager;
        this.jwtManager = jwtManager;
        this.validate = validate;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterModel> register(@RequestBody RegisterRequest req){
        RegisterModel reg = new RegisterModel();
        if (req.getEmail().length()<6 || req.getEmail().length()>32){
            reg.setResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(reg);
        }
        boolean email = Pattern.compile("^([a-zA-Z0-9]+)@([a-zA-Z0-9]+).([a-zA-Z0-9]+)$")
                .matcher(req.getEmail())
                .matches();
        if (!email){
            reg.setResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(reg);
        }

        if (req.getPassword().length<10 || req.getPassword().length>20){
            reg.setResult(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(reg);
        }
        String p = new String(req.getPassword());
        boolean psd = Pattern.compile("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{10,20}$")
                .matcher(p)
                .matches();
        if (!psd){
            reg.setResult(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(reg);
        }

        try{
            authManager.createAndInsertUser(req.getEmail(), req.getPassword());
        }catch (DuplicateKeyException e){
            e.printStackTrace();
            reg.setResult(IDMResults.USER_ALREADY_EXISTS);
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(reg);
        }
        reg.setResult(IDMResults.USER_REGISTERED_SUCCESSFULLY);
        return ResponseEntity.status(HttpStatus.OK)
                .body(reg);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginModel> login(@RequestBody LoginRequest logreq){
        LoginModel log = new LoginModel();
        if (logreq.getEmail().length()<6 || logreq.getEmail().length()>32){
            log.setResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(log);
        }
        boolean email = Pattern.compile("^([a-zA-Z0-9]+)@([a-zA-Z0-9]+).([a-zA-Z0-9]+)$")
                .matcher(logreq.getEmail())
                .matches();
        if (!email){
            log.setResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(log);
        }

        if (logreq.getPassword().length<10 || logreq.getPassword().length>20){
            log.setResult(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(log);
        }
        String p = new String(logreq.getPassword());
        boolean psd = Pattern.compile("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{10,20}$")
                .matcher(p)
                .matches();
        if (!psd){
            log.setResult(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(log);
        }

        try{
            User succ = authManager.selectAndAuthenticateUser(logreq.getEmail(), logreq.getPassword());
            if (succ == null){
                log.setResult(IDMResults.INVALID_CREDENTIALS);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(log);
            }
            else if(succ.getUserStatus() == UserStatus.LOCKED){
                log.setResult(IDMResults.USER_IS_LOCKED);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(log);
            }
            else if(succ.getUserStatus() == UserStatus.BANNED){
                log.setResult(IDMResults.USER_IS_BANNED);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(log);
            }
            else if(succ.getUserStatus() == UserStatus.ACTIVE){
                log.setAccessToken(jwtManager.buildAccessToken(succ));
                RefreshToken refresh = jwtManager.buildRefreshToken(succ);
                authManager.insertRefreshToken(refresh);
                log.setRefreshToken(refresh.getToken());
                log.setResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY);
                return ResponseEntity.status(HttpStatus.OK)
                        .body(log);
            }
            else {
                throw new RuntimeException();
            }
        }catch (IllegalAccessException | JOSEException e){
            log.setResult(IDMResults.USER_NOT_FOUND);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(log);
        }
    }


    @PostMapping("/refresh")
    public ResponseEntity<RefreshModel> refresh(@RequestBody RefreshRequest refq) {
        RefreshModel refreshModel = new RefreshModel();
        // UUID check
        boolean UUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                .matcher(refq.getRefreshToken())
                .matches();
        if (refq.getRefreshToken().length() != 36) {
            refreshModel.setResult(IDMResults.REFRESH_TOKEN_HAS_INVALID_LENGTH);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(refreshModel);
        }
        if (!UUID) {
            refreshModel.setResult(IDMResults.REFRESH_TOKEN_HAS_INVALID_FORMAT);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(refreshModel);
        }

        try {
            RefreshToken retoken = authManager.verifyRefreshToken(refq.getRefreshToken());

            if(retoken.getTokenStatus().equals(TokenStatus.EXPIRED)) {
                refreshModel.setResult(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(refreshModel);
            }
            else if (retoken.getTokenStatus().equals(TokenStatus.REVOKED)){
                refreshModel.setResult(IDMResults.REFRESH_TOKEN_IS_REVOKED);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(refreshModel);
            }
            else {
                Instant current_time = Instant.now();
                if (current_time.isAfter(retoken.getExpireTime()) || current_time.isAfter(retoken.getMaxLifeTime())) {
                    authManager.expireRefreshToken(retoken);
                    refreshModel.setResult(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(refreshModel);
                }
                else {
                    retoken = jwtManager.updateRefreshTokenExpireTime(retoken);
                    authManager.updateRefreshTokenExpireTime(retoken);

                    if (retoken.getExpireTime().isAfter(retoken.getMaxLifeTime())) {
                        authManager.revokeRefreshToken(retoken);

                        User exex = authManager.getUserFromRefreshToken(retoken);
                        RefreshToken renew = jwtManager.buildRefreshToken(exex);
                        authManager.insertRefreshToken(renew);
                        refreshModel.setRefreshToken(renew.getToken());

                        refreshModel.setAccessToken(jwtManager.buildAccessToken(exex));

                        refreshModel.setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN);
                        return ResponseEntity.status(HttpStatus.OK)
                                .body(refreshModel);
                    }
                    else {
                        retoken = jwtManager.updateRefreshTokenExpireTime(retoken);
                        authManager.updateRefreshTokenExpireTime(retoken);

                        refreshModel.setRefreshToken(retoken.getToken());
                        refreshModel.setAccessToken(jwtManager.buildAccessToken(authManager.getUserFromRefreshToken(retoken)));

                        refreshModel.setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN);
                        return ResponseEntity.status(HttpStatus.OK)
                                .body(refreshModel);
                    }
                }
            }
        }
        catch (IllegalAccessException e) {
            if (e.getMessage().equals("Refresh token not found")) {
                refreshModel.setResult(IDMResults.REFRESH_TOKEN_NOT_FOUND);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(refreshModel);
            }
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return null;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthModel> authenticate(@RequestBody AuthRequest auth){
        AuthModel am = new AuthModel();
        String accessToken = auth.getAccessToken();

        try {
            jwtManager.verifyAccessToken(accessToken);
        } catch (ParseException | JOSEException | BadJOSEException e) {
            am.setResult(IDMResults.ACCESS_TOKEN_IS_INVALID);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(am);
        }catch (RuntimeException e){
            am.setResult(IDMResults.ACCESS_TOKEN_IS_EXPIRED);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(am);
        }

        am.setResult(IDMResults.ACCESS_TOKEN_IS_VALID);
        return ResponseEntity.status(HttpStatus.OK)
                .body(am);

    }




}
