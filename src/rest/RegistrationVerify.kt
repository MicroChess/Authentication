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

@Path("/v1/auth/account-register/verify")
class RegistrationVerify {

    private val users: UserService
    private val passwords: PasswordService
    private val tokens: TokenService
    private val otpCodes: RegistrationOtpService

    @Inject constructor(
        users: UserService,
        passwords: PasswordService,
        otpCodes: RegistrationOtpService,
        tokens: TokenService
    ) {
        this.users = users
        this.passwords = passwords
        this.tokens = tokens
        this.otpCodes = otpCodes
    }

    data class RequestBody(
        @field:NotBlank
        val identity: String,

        @field:NotBlank 
        @field:Pattern(regexp = "^\\d{6}\$")
        val otpCode:  String,
    )

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun verify(@Valid request: RequestBody): Response  {
        val account = users.findOrPanic(request.identity)
        when (account.status) {
            UserStatus.PENDING -> {}
            UserStatus.ACTIVE -> return Response.notModified().build()
            else -> throw ForbiddenException("Account is not pending verification")
        }
        val userId = account.id ?: throw IllegalStateException("User ID is null")
        val reference = otpCodes.findOrPanic(userId)
        otpCodes.verifyOtp(request.otpCode, reference)
        val updated = users.markAsVerified(account)
        return tokens.emitAuthorizedResponse(updated)
    }
}
