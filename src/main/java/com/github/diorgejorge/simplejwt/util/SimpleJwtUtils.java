package com.github.diorgejorge.simplejwt.util;

import com.github.diorgejorge.simplejwt.exception.JwtException;
import com.github.diorgejorge.simplejwt.pojo.JwtTokenHelpertInterface;
import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;

/**
 * Created by totvs on 01/11/2016.
 */
public class SimpleJwtUtils {

    private static final String AUTH_HEADER_KEY = "Authorization";
    private static final String AUTH_HEADER_VALUE_PREFIX = "bearer "; // with trailing space to separate util

    public static String createJWT(JwtTokenHelpertInterface subject) {
        Gson gson = new Gson();
        //The JWT signature algorithm we will be using to sign the util
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(subject.getCriptokey());
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        //Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder().setId(subject.getId().toString())
                .setIssuedAt(new Date())
                .setSubject(gson.toJson(subject.getMessage()))
                .setIssuer(subject.getIssuer().toString())
                .signWith(signatureAlgorithm, signingKey);

        //Builds the JWT and serializes it to a compact, URL-safe string
        return AUTH_HEADER_VALUE_PREFIX+builder.compact();
    }

    public static boolean validateJWT(HttpServletRequest request, JwtTokenHelpertInterface tokenControl) throws JwtException {
        String jwt = getBearerToken(request);
        if(jwt == null){
            throw new JwtException("invalid requisition");
        }
        //This line will throw an exception if it is not a signed JWS (as expected)
        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(tokenControl.getCriptokey()))
                .parseClaimsJws(jwt).getBody();
        Gson gson = new Gson();
        JwtTokenHelpertInterface tokenReceived = gson.fromJson(claims.getSubject(), JwtTokenHelpertInterface.class);
        if (tokenReceived.getId().equals(tokenControl.getId())) {
            return true;
        } else {
            throw new JwtException("invalid requisition");
        }
    }

    /**
     * Get the bearer util from the HTTP request.
     * The util is in the HTTP request "Authorization" header in the form of: "Bearer [util]"
     */
    public static String getBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTH_HEADER_KEY);
        if (authHeader != null && authHeader.toLowerCase().startsWith(AUTH_HEADER_VALUE_PREFIX)) {
            return authHeader.substring(AUTH_HEADER_VALUE_PREFIX.length());
        }
        return null;
    }
}
