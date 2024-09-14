package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "example.com/sa-67-example/config"
    "example.com/sa-67-example/controller/genders"
    "example.com/sa-67-example/controller/users"
    "example.com/sa-67-example/middlewares"
    "example.com/sa-67-example/controller/work"
    "example.com/sa-67-example/controller/postwork"
    //resume
    "example.com/sa-67-example/controller/resume"

)

const PORT = "8000"

func main() {
    config.ConnectionDB()
    config.SetupDatabase()

    r := gin.Default()
    r.Use(CORSMiddleware())

    r.POST("/work", middlewares.Authorizes(), work.Create)

    r.POST("/signup", users.SignUp)
    r.POST("/signin", users.SignIn)

    authorized := r.Group("/")
    authorized.Use(middlewares.Authorizes())

    authorized.PUT("/user/:id", users.Update)
    authorized.GET("/users", users.GetAll)
    authorized.GET("/user/:id", users.Get)
    authorized.DELETE("/user/:id", users.Delete)

    authorized.GET("/user/profile", users.GetUserProfile)  // Add this line

    authorized.POST("/works", work.Create)
    authorized.GET("/works", work.GetAll)
    authorized.GET("/work/:id", work.Get)
    authorized.PUT("/work/:id", work.Update)
    authorized.DELETE("/work/:id", work.Delete)

    authorized.GET("/postworks", postwork.GetAll)
    authorized.GET("/postwork/:id", postwork.Get)

    //resume
    authorized.POST("/resumes", resume.CreateResume)
    authorized.GET("/resumes", resume.GetAllResume)
    authorized.GET("/resumes/:id", resume.GetResume)
    authorized.PUT("/resumes/:id", resume.UpdateResume)
    authorized.DELETE("/resumes/:id", resume.DeleteResume)
    
    r.GET("/genders", genders.GetAll)
    r.GET("/", func(c *gin.Context) {
        c.String(http.StatusOK, "API RUNNING... PORT: %s", PORT)
    })

    r.Run("localhost:" + PORT)
}

func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
        c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
        c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }

        c.Next()
    }
}
