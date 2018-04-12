package com.github.diorgejorge.simplejwt.pojo;

import java.io.Serializable;

/**
 * Created by Diorge Jorge on 12/04/2018.
 */
public abstract class AbstractJwtReceiver implements Serializable,JwtReceiverInterface {
    public abstract String getCriptokey ();
    public abstract Object getId();
}
