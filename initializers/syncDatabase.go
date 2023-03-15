package initializers

import "jwt-tokens-mysql/models"

func SyncDatabase() {

	DB.AutoMigrate(&models.User{})

}
