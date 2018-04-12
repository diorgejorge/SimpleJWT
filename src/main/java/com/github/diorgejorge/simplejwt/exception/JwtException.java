package com.github.diorgejorge.simplejwt.exception;

/**
 * Created by Diorge Jorge on 12/04/2018.
 */
public class JwtException  extends Exception{
    public JwtException(String e) {
        super(e);
    }
    public JwtException(Throwable e) {
        super(e);
    }
}
