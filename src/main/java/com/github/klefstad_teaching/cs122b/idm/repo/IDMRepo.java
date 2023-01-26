package com.github.klefstad_teaching.cs122b.idm.repo;

import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Types;

@Component
public class IDMRepo
{
    private final NamedParameterJdbcTemplate template;
    @Autowired
    public IDMRepo(NamedParameterJdbcTemplate template)
    {
        this.template = template;
    }

    public NamedParameterJdbcTemplate getTemplate() {
        return template;
    }

    public User InsertUser(String email, String salt, String hashedpsd){
        try {
            this.template.update(
                    "insert into idm.user(email, user_status_id,salt, hashed_password)" +
                            "values (:email, :user_status_id,:salt, :hashed_password)",
                    new MapSqlParameterSource()
                            .addValue("email", email, Types.VARCHAR)
                            .addValue("user_status_id", UserStatus.ACTIVE, Types.INTEGER)
                            .addValue("salt", salt, Types.CHAR)
                            .addValue("hashed_password", hashedpsd, Types.CHAR)
            );
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public User SelectUser1(String email){
        try {
            User result = this.template.queryForObject(
                    "select id, email, user_status_id, salt, hashed_password from idm.user " +
                            "where email = :email",
                    new MapSqlParameterSource()
                            .addValue("email", email, Types.VARCHAR),
                    (rs, rowNum) ->
                            new User()
                                    .setId(rs.getInt("id"))
            );
            return result;
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }








}
