
/*
|--------------------------------------------------------------------------
| Custom Javascript code
|--------------------------------------------------------------------------
|
| Now that you configured your website, you can write additional Javascript
| code inside the following function. You might want to add more plugins and
| initialize them in this file.
|
*/

$(function() {
    $.getScript("https://cdn.jsdelivr.net/npm/web3@latest/dist/web3.min.js", function () {
        const web3 = new Web3()

    $("#next").hide()
    $("#send").hide()
    $("#loading").hide()
    $("#result").hide()

    var accounts
    var buyResult
    var validateResult
    
    async function onClickConnect() {
        try {
            accounts = await ethereum.request({ method: 'eth_requestAccounts' });
            $("#connect").hide()
            $("#next").show()
          } catch (error) {
            console.error(error);
          }
    }

    $("#connect").on( "click", function() {
        onClickConnect()
    })

    $("#next").on( "click", function() {

        let formData = $("form").serializeArray();

        let formObj = {
            "emails": [formData[0].value],
            "addresses": accounts,
            "product": formData[2].value,
            "expiration": formData[1].value
        }

        $.post( "https://wisdom-bots.com:8181/buy", JSON.stringify(formObj), async function(result) { //http://localhost:8080/buy
            buyResult = await result
            $("#onboarding").hide()
            $("#next").hide()
            $("#send").show()
        }, 'json');

    });

    $("#send").on( "click", async function() {

        let weiVal = parseInt(web3.utils.toWei(buyResult.Value.toString(), "ether")).toString(16)

        const transactionParameters = {
            to: buyResult.WalletAddress, // Required except during contract publications.
            from: ethereum.selectedAddress, // must match user's active address.
            value: weiVal, // Only required to send ether to the recipient from the initiating external account.
        };

        const txHash = await ethereum.request({
            method: 'eth_sendTransaction',
            params: [transactionParameters],
        });

        $("#send").hide()
        $("#loading").show()

        let valObj = {
            "hash": txHash,
            "product": buyResult.Product,
            "expiration": buyResult.Expiration
        }

        $.post( "https://wisdom-bots.com:8181/validate", JSON.stringify(valObj), function(result) { //http://localhost:8080/validate
            validateResult = result

            $("#loading").hide()
            $("#result").show()

            $("#result").html("Your key and download link have been emailed to you. Your product key is: <code>" + validateResult.key + "</code> and is valid until <code>" + validateResult.expiration + "</code>. <a href=" + validateResult.link + ">Download Now</a>")
        }, 'json');    

    })
    })
    
});
