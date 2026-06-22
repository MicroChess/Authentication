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

@Path("/v1/auth/account-register/retry")
class RegistrationRetry {

    private val users: UserService
    private val passwords: PasswordService
    private val tokens: TokenService
    private val otpCodes: RegistrationOtpService
    private val mailing: EmailService

    @Inject constructor(
        users: UserService,
        passwords: PasswordService,
        otpCodes: RegistrationOtpService,
        mailing: EmailService,
        tokens: TokenService
    ) {
        this.users = users
        this.passwords = passwords
        this.tokens = tokens
        this.otpCodes = otpCodes
        this.mailing = mailing
    }

    data class RequestBody(
        @field:NotBlank 
        @field:Email
        val email: String
    )

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun retry(@Valid request: RequestBody): Response  {
        val account = users.findOrPanic(request.email)
        when (account.status) {
            UserStatus.PENDING -> {}
            UserStatus.ACTIVE -> return Response.notModified().build()
            else -> throw ForbiddenException("Account is not pending verification")
        }
        val otpData = otpCodes.createOrRefresh(account.id!!)
        mailing.sendVerificationEmail(request.email, otpData.otp)
        return Response.ok().build()
    }
}
