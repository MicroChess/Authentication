package core

import com.mongodb.client.MongoCollection
import com.mongodb.client.MongoClient
import com.mongodb.client.model.Filters
import com.mongodb.client.model.Updates
import org.eclipse.microprofile.config.inject.ConfigProperty
import com.mongodb.client.model.FindOneAndUpdateOptions
import com.mongodb.client.model.ReturnDocument
import de.mkammerer.argon2.Argon2Factory
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.InternalServerErrorException
import org.bson.types.ObjectId
import model.PasswordModel
import model.UserModel

@ApplicationScoped
class PasswordService {

    private val collection: MongoCollection<PasswordModel>
    private val argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id)

    @Inject constructor(client: MongoClient) {
        this.collection = client.getDatabase("auth")
            .getCollection("passwords", PasswordModel::class.java)
    }

    fun createOrUpdate(plainTextPassword: String, userId: ObjectId): PasswordModel {
        val filter = Filters.eq("userId", userId)
        val passwordChars = plainTextPassword.toCharArray()
        val updates = Updates.combine(
            Updates.set("hash", argon2.hash(3, 65536, 1, passwordChars)),
            Updates.set("timestamp", System.currentTimeMillis())
        )
        val options = FindOneAndUpdateOptions()
            .returnDocument(ReturnDocument.AFTER)
            .upsert(true)
        return collection.findOneAndUpdate(filter, updates, options)
            ?: throw InternalServerErrorException("Failed to create or update password")
    }

    fun findOrPanic(userId: ObjectId): PasswordModel {
        val filter = Filters.eq("userId", userId)
        return collection.find(filter).first()
            ?: throw NotFoundException("Password not found")
    }

    fun verifyPassword(plainPassword: String, password: PasswordModel) {
        if (!argon2.verify(password.hash, plainPassword.toCharArray())) {
            throw ForbiddenException("Invalid Password")
        }
    }

    fun deleteByUserId(userId: org.bson.types.ObjectId) {
        val filter = Filters.eq("userId", userId)
        collection.deleteOne(filter)
    }
}