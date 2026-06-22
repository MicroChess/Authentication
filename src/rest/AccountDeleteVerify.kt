package rest

import com.mongodb.client.MongoClient
import jakarta.ws.rs.core.*
import jakarta.ws.rs.*
import jakarta.inject.*
import java.net.http.*
import org.json.*
import java.net.*
import model.*
import core.*

@Path("/v1/auth/account-delete/verify")
class AccountDeleteVerify {

    private val users: UserService
    private val passwords: PasswordService
    private val tokens: TokenService
    private val otpCodes: AccountDeletionOtpService
    private val registrationOtps: RegistrationOtpService
    private val passwordResetOtps: PasswordResetOtpService
    private val client: MongoClient

    @Inject constructor(
        mongoClient: MongoClient,
        users: UserService,
        passwords: PasswordService,
        otpCodes: AccountDeletionOtpService,
        tokens: TokenService,
        registrationOtps: RegistrationOtpService,
        passwordResetOtps: PasswordResetOtpService
    ) {
        this.client = mongoClient
        this.users = users
        this.passwords = passwords
        this.tokens = tokens
        this.otpCodes = otpCodes
        this.registrationOtps = registrationOtps
        this.passwordResetOtps = passwordResetOtps
    }

    @POST @Produces(MediaType.APPLICATION_JSON)
    fun delete(
        @QueryParam("jwt-token")      queryParam:   String?,
        @HeaderParam("X-Jwt-Token")   customHeader: String?,
        @HeaderParam("Authorization") authHeader:   String?,
        @HeaderParam("X-Otp-Code")    otpCode:      String?
    ): Response {
        val token = tokens.extractAuthenticationToken(queryParam, customHeader, authHeader)
        val model = tokens.parseJsonWebToken(token)
        val userId = model.id!!
        users.ensureAccountStillExists(model)
        val otp = otpCode ?: throw BadRequestException("OTP code is required")
        val reference = otpCodes.findOrPanic(userId)
        otpCodes.verifyOtp(otp, reference)
        client.startSession().use { session ->
            session.withTransaction {
                users.deleteByUserId(userId)
                passwords.deleteByUserId(userId)
                registrationOtps.deleteByUserId(userId)
                passwordResetOtps.deleteByUserId(userId)
                otpCodes.deleteByUserId(userId)
            }
        }
        return Response.ok().build()
    }
}
