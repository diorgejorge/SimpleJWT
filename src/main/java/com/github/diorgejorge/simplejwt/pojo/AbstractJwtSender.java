package com.github.diorgejorge.simplejwt.pojo;

import java.io.Serializable;

/**
 * Created by Diorge Jorge on 12/04/2018.
 */
public abstract class AbstractJwtSender implements Serializable,JwtSenderInterface {
    public abstract String getCriptokey ();
    public abstract Object getMessage();
    public abstract Object getId();
    public abstract Object getIssuer();
}
