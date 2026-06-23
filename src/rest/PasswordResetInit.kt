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
import org.eclipse.microprofile.config.inject.ConfigProperty

@Path("/v1/auth/password-reset/init")
class PasswordResetInit {

    private val users: UserService
    private val passwords: PasswordService
    private val otpCodes: PasswordResetOtpService
    private val mailing: EmailService

    @ConfigProperty(name = "primary.tenant") 
    lateinit var primaryTenant: String

    @Inject constructor(
        users: UserService,
        passwords: PasswordService,
        otpCodes: PasswordResetOtpService,
        mailing: EmailService
    ) {
        this.users = users
        this.passwords = passwords
        this.otpCodes = otpCodes
        this.mailing = mailing
    }

    data class RequestBody(
        @field:NotBlank
        val identity: String,
    )

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun reset(@Valid request: RequestBody): Response  {
        val account = users.findOrPanic(request.identity)
        if (account.tenant != primaryTenant) {
            throw ForbiddenException("Account registered as passwordless")
        }
        val otpData = otpCodes.createOrRefresh(account.id!!)
        mailing.sendPasswordResetEmail(account.email, otpData.otp)
        return Response.ok().build()
    }
}
