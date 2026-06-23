package core

import com.mongodb.client.MongoCollection
import com.mongodb.client.MongoClient
import com.mongodb.client.model.Filters
import com.mongodb.client.model.Updates
import com.mongodb.client.model.FindOneAndUpdateOptions
import com.mongodb.client.model.ReturnDocument
import org.eclipse.microprofile.config.inject.ConfigProperty
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.ws.rs.ClientErrorException
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.InternalServerErrorException

import model.UserModel
import model.UserStatus

@ApplicationScoped
class UserService {

    private val collection: MongoCollection<UserModel>

    @Inject constructor(client: MongoClient) {
        this.collection = client.getDatabase("auth")
            .getCollection("users", UserModel::class.java)
    }

    fun findOrCreate(candidate: UserModel): UserModel {
        val update = Updates.combine(
            Updates.setOnInsert("username", candidate.username),
            Updates.setOnInsert("email", candidate.email),
            Updates.setOnInsert("tenant", candidate.tenant),
            Updates.setOnInsert("status", candidate.status)
        )
        
        val options = FindOneAndUpdateOptions()
            .upsert(true)
            .returnDocument(ReturnDocument.AFTER)
        
        val filter = getMongoFilters(candidate)
        val error = InternalServerErrorException("Failed to create or find user")
        val user = collection.findOneAndUpdate(filter, update, options) ?: throw error
        val retrievedIdentity = Pair(user.username, user.email)
        val expectedIdentity = Pair(candidate.username, candidate.email)
        
        return when(retrievedIdentity) {
            expectedIdentity -> user
            else -> throw ClientErrorException("Username already taken", 409)
        }
    }

    fun markAsVerified(candidate: UserModel): UserModel {
        val update = Updates.combine(
            Updates.set("status", UserStatus.ACTIVE)
        )
        val options = FindOneAndUpdateOptions()
            .upsert(false)
            .returnDocument(ReturnDocument.AFTER)
        val filter = getMongoFilters(candidate)
        return collection.findOneAndUpdate(filter, update, options)
            ?: throw InternalServerErrorException("Failed to mark user as verified")
    }

    fun createOrPanic(candidate: UserModel): UserModel {
        val filter = getMongoFilters(candidate)
        val existing = collection.find(filter).first()
        return when (existing) {
            null -> {
                val result = collection.insertOne(candidate)
                val insertedId = result.insertedId?.asObjectId()?.value
                candidate.copy(id = insertedId)
            }
            else -> throw ClientErrorException("User already exists", 409)
        }
    }

    fun findOrPanic(usernameOrEmail: String): UserModel {
        val filter = getMongoFilters(usernameOrEmail)
        val existing = collection.find(filter).first()
        return existing ?: throw NotFoundException("User not found")
    }

    fun getMongoFilters(usernameOrEmail: String) = Filters.or(
        Filters.eq("username", usernameOrEmail),
        Filters.eq("email", usernameOrEmail)
    )

    fun getMongoFilters(candidate: UserModel) = Filters.or(
        getMongoFilters(candidate.username),
        getMongoFilters(candidate.email)
    )

    fun ensureAccountStillExists(candidate: UserModel) {
        val user = findOrPanic(candidate.username)
        if (user != candidate) {
            throw ForbiddenException("User account no longer exists or has changed")
        }
        if (user.status != model.UserStatus.ACTIVE) {
            throw ForbiddenException("User account is not active")
        }
    }

    fun deleteByUserId(userId: org.bson.types.ObjectId) {
        val filter = Filters.eq("_id", userId)
        collection.deleteOne(filter)
    }
}