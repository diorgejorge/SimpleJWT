package com.github.diorgejorge.simplejwt.pojo;

/**
 * Created by Diorge Jorge on 12/04/2018.
 */
public interface JwtTokenHelpertInterface {
    String getCriptokey ();
    Object getId();
    Object getIssuer();
    Object getMessage();
}
