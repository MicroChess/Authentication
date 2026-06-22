package core

import com.mongodb.client.MongoCollection
import com.mongodb.client.MongoClient
import com.mongodb.client.model.Filters
import com.mongodb.client.model.Updates
import com.mongodb.client.model.FindOneAndUpdateOptions
import com.mongodb.client.model.ReturnDocument
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.InternalServerErrorException
import jakarta.ws.rs.ForbiddenException
import org.bson.types.ObjectId

import model.OtpModel

class GenericOtpService: OtpService {

    private val collection: MongoCollection<OtpModel>
    private val secureRandom = java.security.SecureRandom()

    constructor(client: MongoClient, collectionName: String) {
        this.collection = client.getDatabase("auth")
            .getCollection(collectionName, OtpModel::class.java)
    }

    fun generateOtp(): String {
        val max = 1000000
        val value = secureRandom.nextInt(max)
        return value.toString().padStart(6, '0')
    }

    override fun createOrRefresh(userId: ObjectId): OtpModel {
        val filter = Filters.eq("userId", userId)
        val updates = Updates.combine(
            Updates.set("otp", generateOtp()),
            Updates.inc("iteration", 1),
            Updates.set("timestamp", System.currentTimeMillis()),
            Updates.set("attempts", 0)
        )
        val options = FindOneAndUpdateOptions()
            .returnDocument(ReturnDocument.AFTER)
            .upsert(true)
        return collection.findOneAndUpdate(filter, updates, options)
            ?: throw InternalServerErrorException("Failed to create or update otp")
    }

    override fun findOrPanic(userId: ObjectId): OtpModel {
        val filter = Filters.eq("userId", userId)
        val existing = collection.find(filter).first()
        return existing ?: throw NotFoundException("Otp not found")
    }

    override fun verifyOtp(otpText: String, otpModel: OtpModel) {
        val filter = Filters.eq("_id", otpModel.id)
        val current = collection.find(filter).first()
            ?: throw ForbiddenException("Invalid OTP code")
        if (otpText != current.otp || current.attempts >= 5) {
            collection.updateOne(filter, Updates.inc("attempts", 1))
            throw ForbiddenException("Invalid OTP code")
        }
        collection.updateOne(filter, Updates.set("attempts", 5))
    }

    override fun deleteByUserId(userId: ObjectId) {
        collection.deleteOne(Filters.eq("userId", userId))
    }
}