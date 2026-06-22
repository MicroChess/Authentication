package core

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import java.util.Date
import org.json.JSONObject
import org.bson.types.ObjectId
import jakarta.enterprise.context.ApplicationScoped

import model.UserModel
import model.UserStatus

@ApplicationScoped
class TokenService {

    private val key = Keys.secretKeyFor(SignatureAlgorithm.HS256)

    fun extractAuthenticationToken(
        queryParam: String?, 
        customHeader: String?, 
        authHeader: String?
    ): String {
        val strippedAuthHeader = authHeader?.removePrefix("Bearer ")
        val token = customHeader ?: strippedAuthHeader ?: queryParam
        if (token == null) {
            throw IllegalArgumentException("No token provided")
        }
        val customHeaderMismatch = (customHeader != null && customHeader != token)
        val authHeaderMismatch = (authHeader != null && strippedAuthHeader != token)
        val queryParamMismatch = (queryParam != null && queryParam != token)
        if (customHeaderMismatch || authHeaderMismatch || queryParamMismatch) {
            throw IllegalArgumentException("Multiple tokens provided")
        }
        return token
    }

    fun emitNewToken(user: UserModel): String {
        val now = Date()
        val exp = Date(now.time + 3600_000)
        return Jwts.builder()
            .setSubject(user.username)
            .claim("email", user.email)
            .claim("id", user.id.toString())
            .claim("status", user.status)
            .claim("tenant", user.tenant)
            .setIssuedAt(now)
            .setExpiration(exp)
            .signWith(key)
            .compact()
    }

    fun parseJsonWebToken(token: String): UserModel {
        val claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .body

        return UserModel(
            id = ObjectId(claims["id"] as String),
            username = claims.subject,
            email = claims["email"] as String,
            tenant = claims["tenant"] as String,
            status = UserStatus.valueOf(claims["status"] as String)
        )
    }

    fun emitAuthorizedResponse(user: UserModel): Response {
        val jwt = emitNewToken(user)
        return Response.ok()
            .header("Authorization", "Bearer $jwt")
            .header("X-User-Name", user.username)
            .header("X-User-Email", user.email)
            .header("X-User-ID", user.id.toString())
            .header("X-User-Status", user.status)
            .build()
    }
}