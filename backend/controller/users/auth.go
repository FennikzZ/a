package users


import (

   "errors"

   "net/http"

   "time"


   "github.com/gin-gonic/gin"

   "golang.org/x/crypto/bcrypt"

   "gorm.io/gorm"


   "example.com/sa-67-example/config"

   "example.com/sa-67-example/entity"

   "example.com/sa-67-example/services"

)


type (

   Authen struct {

       Email    string `json:"email"`

       Password string `json:"password"`

   }


   signUp struct {

       FirstName string    `json:"first_name"`

       LastName  string    `json:"last_name"`

       Email     string    `json:"email"`

       Age       uint8     `json:"age"`

       Password  string    `json:"password"`

       BirthDay  time.Time `json:"birthday"`

       GenderID  uint      `json:"gender_id"`

       Address   string     `json:"address"`
       
       Category  string     `json: "category"`

       Wages     uint        `json: "wages"`

       Contact   string       `json: "contact"`

       Profile   string `gorm:"type:longtext"`

   }

)


func SignUp(c *gin.Context) {
    var payload signUp

    // Bind JSON payload to the struct
    if err := c.ShouldBindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    db := config.DB()
    var userCheck entity.Users

    // Check if the user with the provided email already exists
    result := db.Where("email = ?", payload.Email).First(&userCheck)
    if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
        c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
        return
    }

    if userCheck.ID != 0 {
        c.JSON(http.StatusConflict, gin.H{"error": "Email is already registered"})
        return
    }

    // Hash the user's password
    hashedPassword, err := config.HashPassword(payload.Password)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
        return
    }

    // Create a new user
    user := entity.Users{
        FirstName: payload.FirstName,
        LastName:  payload.LastName,
        Email:     payload.Email,
        Age:       payload.Age,
        Password:  hashedPassword,
        BirthDay:  payload.BirthDay,
        GenderID:  payload.GenderID,
        Address:   payload.Address,
        Category:  payload.Category,
        Wages:     payload.Wages,
        Contact:   payload.Contact,
        Profile:   payload.Profile,
    }

    // Save the user to the database
    if err := db.Create(&user).Error; err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Create a new Resume linked to the user
    resume := entity.Resume{
        PersonalID: 0, // ตั้งค่า PersonalID เป็น 0
        StudyID: 0, 
        ExperienceID: 0, 
        SkillID: 0, 
    }

    if err := db.Create(&resume).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create resume"})
        return
    }

    // Update the user's ResumeID
    user.ResumeID = resume.ID
    if err := db.Save(&user).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user with resume ID"})
        return
    }

    c.JSON(http.StatusCreated, gin.H{"message": "Sign-up successful", "resume_id": resume.ID})
}



func SignIn(c *gin.Context) {
    var payload Authen
    var user entity.Users

    if err := c.ShouldBindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // ค้นหา user ด้วย Email
    if err := config.DB().Where("email = ?", payload.Email).First(&user).Error; err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
            return
        }
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // ตรวจสอบรหัสผ่าน
    err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "password is incorrect"})
        return
    }

    jwtWrapper := services.JwtWrapper{
        SecretKey:       "SvNQpBN8y3qlVrsGAYYWoJJk56LtzFHx", // แนะนำให้เก็บใน environment variable
        Issuer:          "AuthService",
        ExpirationHours: 24,
    }

    signedToken, err := jwtWrapper.GenerateToken(user.Email)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "error signing token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token_type": "Bearer", "token": signedToken, "id": user.ID, "resume_id": user.ResumeID})
}
