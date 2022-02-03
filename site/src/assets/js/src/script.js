
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
    var buyLink
    var validateLink
    var newAffiliateLink
    var checkAffiliate

    const PROD = true
    if (PROD) {
        buyLink = "https://wisdom-bots.com:8181/buy"
        validateLink = "https://wisdom-bots.com:8181/validate"
        newAffiliateLink = "https://wisdom-bots.com:8181/newAffiliate"
        checkAffiliate = "https://wisdom-bots.com:8181/checkAffiliate"
    } else {
        buyLink = "http://localhost:8181/buy"
        validateLink = "http://localhost:8181/validate"
        newAffiliateLink = "http://localhost:8181/newAffiliate"
        checkAffiliate = "http://localhost:8181/checkAffiliate"
    }
    
    async function onClickConnect() {
        try {
            accounts = await ethereum.request({ method: 'eth_requestAccounts' });
            $("#connect").html(accounts[0].slice(0,6)+"..."+accounts[0].slice(38))
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

        $.post( buyLink, JSON.stringify(formObj), async function(result) { //http://localhost:8181/buy https://wisdom-bots.com:8181/buy
            buyResult = await result
            $("#onboarding").hide()
            $("#connect").hide()
            $("#next").hide()
            $("#send").show()
        }, 'json');

    });

    $("#existingAffiliateNext").on( "click", function() {

        let formData = $("#existingAffiliateForm").serializeArray();

        let formObj = {
            "affiliatePrivateCode": formData[0].value
        }

        $.post( checkAffiliate, JSON.stringify(formObj), async function(result) { //http://localhost:8181/buy https://wisdom-bots.com:8181/buy
            buyResult = await result
            $("#existingAffiliateForm").hide()
            $("#existingAffiliateNext").hide()
            $("#existingAffiliateError").hide()
            $("#existingAffiliateResult").html("Your code "+buyResult.affiliateCode+" has earned "+buyResult.affiliateEarnings+" BNB. Your commission rate is "+buyResult.affiliatePercent+"%. Your address is "+buyResult.affiliateAddress+".")
        }, 'json')
        .fail(function(jqXHR) {
            $("#existingAffiliateError").html(jqXHR.responseJSON)
        });

    });

    $("#newAffiliateNext").on( "click", function() {

        let formData = $("#newAffiliateForm").serializeArray();

        let formObj = {
            "affiliateAddress": formData[1].value,
            "affiliateCode": formData[0].value
        }

        $.post( newAffiliateLink, JSON.stringify(formObj), async function(result) { //http://localhost:8181/buy https://wisdom-bots.com:8181/buy
            buyResult = await result
            console.log(buyResult)
            $("#newAffiliateForm").hide()
            $("#newAffiliateNext").hide()
            $("#newAffiliateError").hide()
            $("#newAffiliateResult").html("Your private affiliate code is <code>"+buyResult.AffiliatePrivateCode+"</code>. Use this to check your earnings. Your address is <code>"+buyResult.Address+"</code>. Share the link <code>https://wisdom-bots.com?affiliate="+buyResult.Code+"</code> to earn.")
        }, 'json')
        .fail(function(jqXHR) {
            $("#newAffiliateError").html(jqXHR.responseJSON)
        });

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

        const params = new Proxy(new URLSearchParams(window.location.search), {
            get: (searchParams, prop) => searchParams.get(prop),
        });

        let affiliate = params.affiliate

        let valObj = {
            "hash": txHash,
            "product": buyResult.Product,
            "expiration": buyResult.Expiration,
            "affiliate": affiliate
        }

        $.post( validateLink, JSON.stringify(valObj), function(result) { //http://localhost:8181/validate https://wisdom-bots.com:8181/validate
            validateResult = result

            $("#loading").hide()
            $("#result").show()

            $("#result").html("Your key and download link have been emailed to you. Your product key is: <code>" + validateResult.key + "</code> and is valid until <code>" + validateResult.expiration + "</code>. <a href=" + validateResult.link + ">Download Now</a>")
        }, 'json');    

    })
    })
    
});
