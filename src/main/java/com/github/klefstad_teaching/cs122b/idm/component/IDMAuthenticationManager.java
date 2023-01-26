package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.repo.IDMRepo;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

@Component
public class IDMAuthenticationManager
{
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String       HASH_FUNCTION = "PBKDF2WithHmacSHA512";

    private static final int ITERATIONS     = 10000;
    private static final int KEY_BIT_LENGTH = 512;

    private static final int SALT_BYTE_LENGTH = 4;

    public final IDMRepo repo;


    @Autowired
    public IDMAuthenticationManager(IDMRepo repo)
    {
        this.repo = repo;
    }

    private static byte[] hashPassword(final char[] password, String salt)
    {
        return hashPassword(password, Base64.getDecoder().decode(salt));
    }

    private static byte[] hashPassword(final char[] password, final byte[] salt)
    {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_FUNCTION);

            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);

            SecretKey key = skf.generateSecret(spec);

            return key.getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] genSalt()
    {
        byte[] salt = new byte[SALT_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public User selectAndAuthenticateUser(String email, char[] password)
            throws IllegalAccessException

    {
        String sql = "select id, email, user_status_id, salt, hashed_password " +
                "from idm.user " +
                "where email = :email";
        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("email", email, Types.VARCHAR);
        List<User> users = repo.getTemplate().query(
                sql,
                source,
                (rs, rowNum) ->
                        new User()
                                .setId(rs.getInt("id"))
                                .setEmail(rs.getString("email"))
                                .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                .setSalt(rs.getString("salt"))
                                .setHashedPassword(rs.getString("hashed_password"))
        );
        if (users.isEmpty()){
            throw new IllegalAccessException("Not found");
        }
        User user = users.get(0);
        SecretKeyFactory skf = null;
        try {
            skf = SecretKeyFactory.getInstance (HASH_FUNCTION);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] salt = Base64.getDecoder().decode(user.getSalt());
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);
        SecretKey key = null;
        try {
            key = skf.generateSecret(spec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        byte[] encodedPassword = key.getEncoded();
        String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(encodedPassword);

        if (user.getHashedPassword().equals(base64EncodedHashedPassword)){
            return user;
        }

        return null;
    }

    public void createAndInsertUser(String email, char[] password)
            throws DuplicateKeyException
    {
        SecretKeyFactory skf = null;
        try {
            skf = SecretKeyFactory.getInstance (HASH_FUNCTION);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] salt = genSalt();
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);
        SecretKey key = null;
        try {
            key = skf.generateSecret(spec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        byte[] encodedPassword = key.getEncoded();
        String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(encodedPassword);
        String base64EncodedHashedSalt = Base64.getEncoder().encodeToString(salt);

        String sql = "insert into idm.user(email, user_status_id,salt, hashed_password)" +
                "values (:email, :user_status_id,:salt, :hashed_password)";

        MapSqlParameterSource source = new MapSqlParameterSource()
                .addValue("email", email, Types.VARCHAR)
                .addValue("user_status_id", UserStatus.ACTIVE.id(), Types.INTEGER)
                .addValue("salt", base64EncodedHashedSalt, Types.CHAR)
                .addValue("hashed_password", base64EncodedHashedPassword, Types.CHAR);
        repo.getTemplate().update(sql, source);

    }

    public void insertRefreshToken(RefreshToken refreshToken)
    {
        String sql = "INSERT into idm.refresh_token(token, user_id, token_status_id, expire_time, max_life_time)" +
                "values (:token, :user_id, :token_status_id, :expire_time, :max_life_time)";
        MapSqlParameterSource source = new MapSqlParameterSource()
                .addValue("token", refreshToken.getToken(), Types.CHAR)
                .addValue("user_id", refreshToken.getUserId(), Types.INTEGER)
                .addValue("token_status_id", refreshToken.getTokenStatus().id(), Types.INTEGER)
                .addValue("expire_time", Timestamp.from(refreshToken.getExpireTime()), Types.TIMESTAMP)
                .addValue("max_life_time",Timestamp.from(refreshToken.getMaxLifeTime()), Types.TIMESTAMP);

        repo.getTemplate().update(sql, source);
    }

    public RefreshToken verifyRefreshToken(String token) throws IllegalAccessException {

        String sql = "select id, token, user_id, token_status_id, expire_time, max_life_time " +
                "from idm.refresh_token " +
                "where token = :token";
        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("token", token, Types.VARCHAR);
        List<RefreshToken> tokens = repo.getTemplate().query(
                sql,
                source,
                (rs, rowNum) ->
                        new RefreshToken()
                                .setId(rs.getInt("id"))
                                .setToken(rs.getString("token"))
                                .setUserId(rs.getInt("user_id"))
                                .setTokenStatus(TokenStatus.fromId(rs.getInt("token_status_id")))
                                .setExpireTime(rs.getTimestamp("expire_time").toInstant())
                                .setMaxLifeTime(rs.getTimestamp("max_life_time").toInstant())
        );
        if (tokens.isEmpty()){
            throw new IllegalAccessException("Refresh token not found");
        }
        RefreshToken retoken = tokens.get(0);
        return retoken;
    }

    public void updateRefreshTokenExpireTime(RefreshToken token)
    {
        String sql = "update idm.refresh_token " +
                "set expire_time =:expire_time " +
                "where token = :token";
        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("expire_time", Timestamp.from(token.getExpireTime()), Types.TIMESTAMP)
                        .addValue("token", token.getToken(), Types.CHAR);
        repo.getTemplate().update(sql, source);
    }

    public void expireRefreshToken(RefreshToken token)
    {
        String sql = "update idm.refresh_token " +
                "set token_status_id = :token_status " +
                "where token = :token";
        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("token_status", TokenStatus.EXPIRED.id(), Types.INTEGER)
                        .addValue("token", token.getToken(), Types.CHAR);
        repo.getTemplate().update(sql, source);
    }

    public void revokeRefreshToken(RefreshToken token)
    {
        String sql = "update idm.refresh_token " +
                "set token_status_id = :token_status " +
                "where token = :token";
        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("token_status", TokenStatus.REVOKED.id(), Types.INTEGER)
                        .addValue("token", token.getToken(), Types.CHAR);
        repo.getTemplate().update(sql, source);
    }

    public User getUserFromRefreshToken(RefreshToken refreshToken)
    {
        String sql = "select `user`.id, email, user_status_id, salt, hashed_password " +
                "from idm.user, idm.refresh_token " +
                "where `user`.id = :refreshid";
        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("refreshid", refreshToken.getUserId(), Types.VARCHAR);
        List<User> users = repo.getTemplate().query(
                sql,
                source,
                (rs, rowNum) ->
                        new User()
                                .setId(rs.getInt("id"))
                                .setEmail(rs.getString("email"))
                                .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                .setSalt(rs.getString("salt"))
                                .setHashedPassword(rs.getString("hashed_password"))
        );
        return users.get(0);
    }
}
