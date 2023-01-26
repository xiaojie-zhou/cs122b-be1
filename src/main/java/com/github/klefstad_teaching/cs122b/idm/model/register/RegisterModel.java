package com.github.klefstad_teaching.cs122b.idm.model.register;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.github.klefstad_teaching.cs122b.core.result.BasicResults;
import com.github.klefstad_teaching.cs122b.core.result.Result;


import javax.websocket.RemoteEndpoint;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class RegisterModel {
    private Result result;

    public Result getResult() {
        return result;
    }

    public void setResult(Result result) {
        this.result = result;
    }
}
