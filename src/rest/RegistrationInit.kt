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

@Path("/v1/auth/account-register/init")
class RegistrationInit {

    private val users: UserService
    private val passwords: PasswordService
    private val tokens: TokenService
    private val otpCodes: RegistrationOtpService
    private val mailing: EmailService
    private val tenant: String

    @Inject constructor(
        users: UserService,
        passwords: PasswordService,
        otpCodes: RegistrationOtpService,
        mailing: EmailService,
        tokens: TokenService,
        @ConfigProperty(name = "microchess.tenant") tenant: String
    ) {
        this.users = users
        this.passwords = passwords
        this.tokens = tokens
        this.otpCodes = otpCodes
        this.mailing = mailing
        this.tenant = tenant
    }

    data class RequestBody(
        @field:NotBlank 
        @field:Size(min = 3, max = 50) 
        @field:Pattern(regexp = "^[a-zA-Z0-9_-]+\$")
        val username: String,

        @field:NotBlank 
        @field:Email
        val email: String,

        @field:NotBlank 
        @field:Size(min = 8)
        val password: String,
    )

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun register(@Valid request: RequestBody): Response  {
        val user = UserModel(
            username = request.username,
            email = request.email,
            tenant = tenant,
            status = UserStatus.PENDING
        )
        val created = users.createOrPanic(user)
        passwords.createOrUpdate(request.password, created.id!!)
        val otpData = otpCodes.createOrRefresh(created.id)
        mailing.sendVerificationEmail(request.email, otpData.otp)
        return Response.ok().build()
    }
}
