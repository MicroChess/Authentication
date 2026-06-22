package core

import com.mongodb.client.*
import com.mongodb.client.model.*
import com.mongodb.client.result.*
import org.bson.types.*
import jakarta.enterprise.context.*
import jakarta.inject.*
import jakarta.ws.rs.*
import model.*

interface OtpService {
    fun findOrPanic(userId: ObjectId): OtpModel
    fun createOrRefresh(userId: ObjectId): OtpModel
    fun verifyOtp(otpText: String, otpModel: OtpModel)
    fun deleteByUserId(userId: ObjectId)
}

@ApplicationScoped
class RegistrationOtpService 
    @Inject constructor(client: MongoClient)
        : OtpService by GenericOtpService(client, "registration-otps")

@ApplicationScoped
class PasswordResetOtpService 
    @Inject constructor(client: MongoClient)
        : OtpService by GenericOtpService(client, "password-reset-otps")

@ApplicationScoped
class AccountDeletionOtpService 
    @Inject constructor(client: MongoClient)
        : OtpService by GenericOtpService(client, "account-deletion-otps")