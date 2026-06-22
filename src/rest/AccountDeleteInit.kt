package rest

import jakarta.ws.rs.core.*
import jakarta.ws.rs.*
import jakarta.inject.*
import java.net.http.*
import org.json.*
import java.net.*
import model.*
import core.*

@Path("/v1/auth/account-delete/init")
class AccountDeleteInit {

    private val users: UserService
    private val tokens: TokenService
    private val otpCodes: AccountDeletionOtpService
    private val mailing: EmailService

    @Inject constructor(
        users: UserService,
        otpCodes: AccountDeletionOtpService,
        mailing: EmailService,
        tokens: TokenService
    ) {
        this.users = users
        this.tokens = tokens
        this.otpCodes = otpCodes
        this.mailing = mailing
    }

    @POST @Produces(MediaType.APPLICATION_JSON)
    fun delete(
        @QueryParam("jwt-token")      queryParam:   String?,
        @HeaderParam("X-Jwt-Token")   customHeader: String?,
        @HeaderParam("Authorization") authHeader:   String?
    ): Response  {
        val token = tokens.extractAuthenticationToken(queryParam, customHeader, authHeader)
        val model = tokens.parseJsonWebToken(token)
        users.ensureAccountStillExists(model)
        val otpData = otpCodes.createOrRefresh(model.id!!)
        mailing.sendAccountDeletetionVerificationEmail(model.email, otpData.otp)
        return Response.ok().build()
    }
}