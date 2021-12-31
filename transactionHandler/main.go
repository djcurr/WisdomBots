package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"modules/licensing"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	_ "github.com/go-sql-driver/mysql"
	gomail "gopkg.in/mail.v2"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type user struct {
	ID            primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	WalletAddress string             `json:"walletAddress"`
	WalletKey     string             `json:"walletKey"`
	Emails        []string           `json:"emails"`
	Addresses     []string           `json:"addresses"`
	Product       string             `json:"product"`
	Expiration    string             `json:"expiration"`
	Keys          []keys             `json:"keys"`
	Hashes        []string           `json:"hashes"`
}

type keys struct {
	Product    string `json:"product"`
	Key        string `json:"key"`
	Expiration string `json:"expiration"`
}

type initialResponse struct {
	WalletAddress string
	Value         string
	Expiration    string
	Product       string
}

type transaction struct {
	Hash       string
	Product    string
	Expiration string
}

var mongoClient *mongo.Client
var coll *mongo.Collection

func main() {
	var err error
	mongoClient, err = mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb+srv://test:test123@wisdombots.vpyln.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"))
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := mongoClient.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()

	coll = mongoClient.Database("wisdombots").Collection("transactions")

	router := gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true

	router.Use(cors.New(config))
	router.POST("/buy", postUser)
	router.POST("/validate", validate)

	router.Run("localhost:8080")
}

func postUser(c *gin.Context) {
	var newUser user

	err := c.BindJSON(&newUser)
	if err != nil {
		return
	}

	opts := options.Count().SetLimit(1)

	emailFilter := bson.D{primitive.E{Key: "emails", Value: newUser.Emails[0]}}
	emailExists, _ := coll.CountDocuments(context.TODO(), emailFilter, opts)

	addressFilter := bson.D{primitive.E{Key: "addresses", Value: newUser.Addresses[0]}}
	addressExists, _ := coll.CountDocuments(context.TODO(), addressFilter, opts)

	fmt.Println(addressExists, emailExists)

	if emailExists == 0 && addressExists == 1 {

		filter := bson.D{primitive.E{Key: "addresses", Value: newUser.Addresses[0]}}

		update := bson.M{"$push": bson.D{primitive.E{Key: "emails", Value: newUser.Emails[0]}}}

		_, err = coll.UpdateOne(context.TODO(), filter, update)
		if err != nil {
			panic(err)
		}

		var existingUser user
		existingFilter := bson.D{primitive.E{Key: "addresses", Value: newUser.Addresses[0]}}

		err = coll.FindOne(context.TODO(), existingFilter).Decode(&existingUser)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				// This error means your query did not match any documents.
				fmt.Println("no document found")
			}
			panic(err)
		}

		value := value(newUser.Product, newUser.Expiration)

		response := initialResponse{
			WalletAddress: existingUser.WalletAddress,
			Value:         value,
			Product:       newUser.Product,
			Expiration:    newUser.Expiration,
		}

		c.IndentedJSON(http.StatusCreated, response)

	} else if addressExists == 0 && emailExists == 1 {

		filter := bson.D{primitive.E{Key: "emails", Value: newUser.Emails[0]}}

		update := bson.M{"$push": bson.D{primitive.E{Key: "addresses", Value: newUser.Addresses[0]}}}

		_, err = coll.UpdateOne(context.TODO(), filter, update)
		if err != nil {
			panic(err)
		}

		var existingUser user
		existingFilter := bson.D{primitive.E{Key: "emails", Value: newUser.Emails[0]}}

		err = coll.FindOne(context.TODO(), existingFilter).Decode(&existingUser)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				// This error means your query did not match any documents.
				fmt.Println("no document found")
			}
			panic(err)
		}

		value := value(newUser.Product, newUser.Expiration)

		response := initialResponse{
			WalletAddress: existingUser.WalletAddress,
			Value:         value,
			Product:       newUser.Product,
			Expiration:    newUser.Expiration,
		}

		c.IndentedJSON(http.StatusCreated, response)

	} else if addressExists == 0 && emailExists == 0 {
		privKey, address := generateWallet()
		value := value(newUser.Product, newUser.Expiration)

		doc := bson.D{primitive.E{Key: "emails", Value: newUser.Emails}, primitive.E{Key: "addresses", Value: newUser.Addresses}, primitive.E{Key: "walletAddress", Value: address}, primitive.E{Key: "walletKey", Value: privKey}}

		_, err = coll.InsertOne(context.TODO(), doc)
		if err != nil {
			panic(err)
		}

		response := initialResponse{
			WalletAddress: address,
			Value:         value,
			Product:       newUser.Product,
			Expiration:    newUser.Expiration,
		}

		c.IndentedJSON(http.StatusCreated, response)

	} else if addressExists == 1 && emailExists == 1 {

		var existingUser user
		existingFilter := bson.D{primitive.E{Key: "emails", Value: newUser.Emails[0]}}

		err = coll.FindOne(context.TODO(), existingFilter).Decode(&existingUser)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				// This error means your query did not match any documents.
				fmt.Println("no document found")
			}
			panic(err)
		}

		value := value(newUser.Product, newUser.Expiration)

		response := initialResponse{
			WalletAddress: existingUser.WalletAddress,
			Value:         value,
			Product:       newUser.Product,
			Expiration:    newUser.Expiration,
		}

		c.IndentedJSON(http.StatusCreated, response)

	}

}

func validate(c *gin.Context) {
	var newTransaction transaction

	if err := c.BindJSON(&newTransaction); err != nil {
		return
	}
	genKey, expiration := validateTx(newTransaction.Hash, newTransaction.Product, newTransaction.Expiration)

	response := bson.M{"key": genKey, "expiration": expiration}
	c.IndentedJSON(http.StatusCreated, response)
}

func generateWallet() (string, string) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	return fmt.Sprint(hexutil.Encode(privateKeyBytes)[2:]), fmt.Sprint(address)
}

func value(product string, expiration string) string {
	if product == "Presale Bot" && expiration == "monthly" {
		return "0.001"
	} else if product == "Presale Bot" && expiration == "lifetime" {
		return "0.001"
	} else if product == "Telegram Bot" && expiration == "monthly" {
		return "0.001"
	} else if product == "Telegram Bot" && expiration == "lifetime" {
		return "0.001"
	} else {
		return "0"
	}
}

func bigValue(product string, expiration string) *big.Int {
	if product == "Presale Bot" && expiration == "monthly" {
		return toWei(0.001)
	} else if product == "Presale Bot" && expiration == "lifetime" {
		return toWei(0.001)
	} else if product == "Telegram Bot" && expiration == "monthly" {
		return toWei(0.001)
	} else if product == "Telegram Bot" && expiration == "lifetime" {
		return toWei(0.001)
	} else {
		return toWei(0)
	}
}

func validateTx(hash string, product string, expiration string) (string, string) {
	client, err := ethclient.Dial("https://data-seed-prebsc-1-s1.binance.org:8545/")
	if err != nil {
		panic(err)
	}

	value := bigValue(product, expiration)

	newHash := common.HexToHash(hash)

	tx, isPending, err := client.TransactionByHash(context.Background(), newHash)
	if err != nil {
		panic(err)
	}

	signer := types.NewEIP155Signer(tx.ChainId())

	sender, err := signer.Sender(tx)
	if err != nil {
		panic(err)
	}

	var result user
	fmt.Println(sender)
	filter := bson.D{primitive.E{Key: "addresses", Value: fmt.Sprint(sender)}}

	err = coll.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// This error means your query did not match any documents.
			fmt.Println("no document found from address")
		}
		panic(err)
	}

	var updateKeys keys

	opts := options.Count().SetLimit(1)
	hashFilter := bson.D{primitive.E{Key: "hashes", Value: hash}}
	exists, _ := coll.CountDocuments(context.TODO(), hashFilter, opts)
	if tx.Value().Cmp(value) == 1 ||
		tx.Value().Cmp(value) == 0 &&
			*tx.To() == common.HexToAddress(result.WalletAddress) &&
			exists != 1 {
		var counter int
		for isPending {
			_, isPending, err = client.TransactionByHash(context.Background(), newHash)
			if err != nil {
				panic(err)
			}
			if counter == 10 {
				fmt.Println("panic")
				log.Panic("timeout")
			}
			fmt.Println("pending")
			counter += 1
			time.Sleep(time.Second)
		}
		key, expirationDate := generateLicense(product, expiration)
		sendEmail(result.Emails[len(result.Emails)-1], key, product, expiration)
		updateKeys = keys{
			Product:    product,
			Key:        key,
			Expiration: expirationDate,
		}

		filterId := bson.M{"_id": bson.M{"$eq": result.ID}}
		update := bson.M{"$push": bson.D{primitive.E{Key: "keys", Value: bson.D{primitive.E{Key: "product", Value: updateKeys.Product}, {Key: "key", Value: updateKeys.Key}, primitive.E{Key: "expiration", Value: expiration}}}, primitive.E{Key: "hashes", Value: hash}}}
		_, err = coll.UpdateOne(context.TODO(), filterId, update)
		if err != nil {
			panic(err)
		}
	}
	return updateKeys.Key, updateKeys.Expiration
}

func toWei(value float64) *big.Int {
	return big.NewInt(int64(value * (math.Pow(10.0, 18.0))))
}

func generateLicense(product string, expiration string) (string, string) {
	// db, err = sql.Open("mysql", USERNAME+":"+PASSWORD+"@tcp("+HOST+")/"+DATABASE)
	rand.Seed(time.Now().UnixNano())
	db, err := sql.Open("mysql", "dumb:wisdom@tcp(localhost:3306)/wisdomBots")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println("[!] ERROR: CHECK IF MYSQL SERVER IS ONLINE! [!]")
		os.Exit(0)
	}

	license := randomString(4) + "-" + randomString(4) + "-" + randomString(4)

	tmpemail := "example@example.com"
	email := "example@example.com"
	key := "36da890059bbe90d71edbb86a7fcb2fbb82d2d8692b54bb6b95bc454ae667800"
	var licenseTable string
	var expirationDate string

	if product == "Presale Bot" && expiration == "monthly" {
		licenseTable = "presaleBotLicenses"
		expirationDate = time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	} else if product == "Presale Bot" && expiration == "lifetime" {
		licenseTable = "presaleBotLicenses"
		expirationDate = time.Now().AddDate(80, 0, 0).Format("2006-01-02")
	} else if product == "Telegram Bot" && expiration == "monthly" {
		licenseTable = "telegramBotLicenses"
		expirationDate = time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	} else if product == "Telegram Bot" && expiration == "lifetime" {
		licenseTable = "telegramBotLicenses"
		expirationDate = time.Now().AddDate(80, 0, 0).Format("2006-01-02")
	}

	err = db.QueryRow("SELECT email FROM " + licenseTable + " WHERE license='" + license + "'").Scan(&tmpemail)
	if err == sql.ErrNoRows {
		_, err = db.Exec("INSERT INTO "+licenseTable+"(email, license, experation, ip) VALUES(?, ?, ?, ?)", email, license, expirationDate, "none")
		if err != nil {
			fmt.Println("[!] ERROR: UNABLE TO INSERT INTO DATABASE [!]")
		} else {
			fmt.Println("License already in database?")
			fmt.Println("License:", licensing.Encrypt(key, license))
		}
	}
	return licensing.Encrypt(key, license), expirationDate
}

func randomString(n int) string {
	var letterBytes = []rune("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func sendEmail(to string, key string, product string, expiration string) {
	m := gomail.NewMessage()

	// Set E-Mail sender
	m.SetHeader("From", "djcurr@aol.com")

	// Set E-Mail receivers
	m.SetHeader("To", to)

	// Set E-Mail subject
	m.SetHeader("Subject", "WisdomBots Product Key")

	// Set E-Mail body. You can set plain text or html with text/html
	m.SetBody("text/plain", "Your activation key for "+product+" is: "+key+" and expires on"+expiration+" UTC")

	// Settings for SMTP server
	d := gomail.NewDialer("smtp.aol.com", 465, "djcurr@aol.com", "onqpjlkchatkwbqa")

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// Now send E-Mail
	if err := d.DialAndSend(m); err != nil {
		fmt.Println(err)
		panic(err)
	}

}
