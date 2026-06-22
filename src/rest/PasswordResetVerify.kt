package rest

import jakarta.ws.rs.core.*
import jakarta.ws.rs.*
import jakarta.inject.*
import java.net.http.*
import org.json.*
import java.net.*
import model.*
import core.*
import jakarta.validation.Valid
import jakarta.validation.constraints.*

@Path("/v1/auth/password-reset/verify")
class PasswordResetVerify {

    private val users: UserService
    private val passwords: PasswordService
    private val tokens: TokenService
    private val otpCodes: PasswordResetOtpService

    @Inject constructor(
        users: UserService,
        passwords: PasswordService,
        otpCodes: PasswordResetOtpService,
        tokens: TokenService
    ) {
        this.users = users
        this.passwords = passwords
        this.tokens = tokens
        this.otpCodes = otpCodes
    }

    data class RequestBody(
        @field:NotBlank
        val identity:    String,

        @field:NotBlank @field:Pattern(regexp = "^\\d{6}\$")
        val otpCode:     String,

        @field:NotBlank @field:Size(min = 8)
        val newPassword: String,
    )

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun verify(@Valid request: RequestBody): Response  {
        val account = users.findOrPanic(request.identity)
        val reference = otpCodes.findOrPanic(account.id!!)
        otpCodes.verifyOtp(request.otpCode, reference)
        passwords.createOrUpdate(request.newPassword, account.id)
        return tokens.emitAuthorizedResponse(account)
    }
}
