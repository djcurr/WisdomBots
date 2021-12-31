
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

        $.post( "http://localhost:8080/buy", JSON.stringify(formObj), function(result) {
            buyResult = result
        }, 'json');

        $("#onboarding").hide()
        $("#next").hide()
        $("#send").show()

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

        $.post( "http://localhost:8080/validate", JSON.stringify(valObj), function(result) {
            validateResult = result

            $("#loading").hide()
            $("#result").show()

            $("#result").html("Your key is: <code>" + validateResult.key + "</code> and expires on <code>" + validateResult.expiration + "</code>")
        }, 'json');    

    })
    
});
