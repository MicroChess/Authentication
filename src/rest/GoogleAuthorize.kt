package rest

import jakarta.ws.rs.core.*
import jakarta.ws.rs.*
import jakarta.inject.*
import java.net.http.*
import org.json.*
import java.net.*
import model.*
import core.*
import org.eclipse.microprofile.config.inject.ConfigProperty

const val GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"

@Path("/v1/auth/authorize/google")
class GoogleAuthorize {

    private val users: UserService
    private val tokens: TokenService
    private val tenant: String

    @Inject constructor(
        users: UserService,
        tokens: TokenService,
        @ConfigProperty(name = "microchess.tenant") tenant: String
    ) {
        this.users = users
        this.tokens = tokens
        this.tenant = tenant
    }

    @POST @Produces(MediaType.APPLICATION_JSON)
    fun authorize(
        @QueryParam("oauth-token")    queryParam:   String?,
        @HeaderParam("X-OAuth-Token") customHeader: String?,
        @HeaderParam("Authorization") authHeader:   String?
    ): Response  {
        val token = tokens.extractAuthenticationToken(queryParam, customHeader, authHeader)
        val userInfo = googleOAuthDecode(token)
        val json = JSONObject(userInfo)
        if (!json.getBoolean("email_verified")) {
            throw ForbiddenException("Google account email is not verified")
        }
        val email = json.getString("email")
        val model = defaultUserModel(email)
        val result = users.findOrCreate(model)
        ensureAccountIsActive(result)
        return tokens.emitAuthorizedResponse(result)
    }

    private fun ensureAccountIsActive(candidate: UserModel) {
        if (candidate.status != UserStatus.ACTIVE) {
            throw ForbiddenException("User account is not active")
        }
    }

    private fun defaultUserModel(email: String) = UserModel(
        username = email,
        email = email,
        tenant = tenant,
        status = UserStatus.ACTIVE
    )

    private fun googleOAuthDecode(token: String): String {
        val request = HttpRequest.newBuilder()
            .uri(URI.create(GOOGLE_USERINFO_ENDPOINT))
            .header("Authorization", "Bearer $token")
            .GET()
            .build()

        val client = HttpClient.newHttpClient()
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        return when (response.statusCode()) {
            200 -> response.body()
            else -> throw ForbiddenException(response.body())
        }
    }
}
