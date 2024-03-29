// Code generated by go-swagger; DO NOT EDIT.

package verification

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// VerifyChallengeDepositReader is a Reader for the VerifyChallengeDeposit structure.
type VerifyChallengeDepositReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *VerifyChallengeDepositReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewVerifyChallengeDepositOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewVerifyChallengeDepositBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewVerifyChallengeDepositUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewVerifyChallengeDepositNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewVerifyChallengeDepositOK creates a VerifyChallengeDepositOK with default headers values
func NewVerifyChallengeDepositOK() *VerifyChallengeDepositOK {
	return &VerifyChallengeDepositOK{}
}

/*VerifyChallengeDepositOK handles this case with default header values.

OK
*/
type VerifyChallengeDepositOK struct {
	Payload *models.VerificationResponse
}

func (o *VerifyChallengeDepositOK) Error() string {
	return fmt.Sprintf("[PUT /verification][%d] verifyChallengeDepositOK  %+v", 200, o.Payload)
}

func (o *VerifyChallengeDepositOK) GetPayload() *models.VerificationResponse {
	return o.Payload
}

func (o *VerifyChallengeDepositOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.VerificationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewVerifyChallengeDepositBadRequest creates a VerifyChallengeDepositBadRequest with default headers values
func NewVerifyChallengeDepositBadRequest() *VerifyChallengeDepositBadRequest {
	return &VerifyChallengeDepositBadRequest{}
}

/*VerifyChallengeDepositBadRequest handles this case with default header values.

Y901 : Service not supported<br>Y812 : Required field/value - verification.verificationType missing in the verificationParam<br>Y812 : Required field/value - amount.amount missing in the verificationParam<br>Y812 : Required field/value - baseType missing in the verificationParam<br>Y812 : Required field/value - currency missing in the verificationParam<br>Y812 : Required field/value - providerAccountId missing in the verificationParam<br>Y812 : Required field/value - accountId missing in the verificationParam<br>Y800 : Invalid value for verificationParam<br>Y800 : Invalid value for verification.verificationType<br>Y800 : Invalid value for baseType<br>Y800 : Invalid value for providerAccountId<br>Y800 : Invalid value for accountId<br>Y813 : Transaction should be provided<br>Y801 : Invalid length for accountNumber<br>Y801 : Invalid length for amount<br>Y835 : Account(s) not eligible for Challenge Deposit verification<br>Y806 : Invalid Input<br>Y840 : Verification has been initiated already<br>Y837 : Account has been verified already<br>Y838 : The currency code provided does not match with the currency of the transaction executed on the target account<br>Y846 : The number of financial transactions made on the target account does not match with the number of transactions entered by the user.<br>Y842 : Number of retries exceeded the maximum Challenge Deposit verification limit<br>Y844 : Financial Instructions were not executed successfully on the target account<br>Y845 : Verification time expired. Please try initiating challenge deposit again
*/
type VerifyChallengeDepositBadRequest struct {
	Payload *models.YodleeError
}

func (o *VerifyChallengeDepositBadRequest) Error() string {
	return fmt.Sprintf("[PUT /verification][%d] verifyChallengeDepositBadRequest  %+v", 400, o.Payload)
}

func (o *VerifyChallengeDepositBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *VerifyChallengeDepositBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewVerifyChallengeDepositUnauthorized creates a VerifyChallengeDepositUnauthorized with default headers values
func NewVerifyChallengeDepositUnauthorized() *VerifyChallengeDepositUnauthorized {
	return &VerifyChallengeDepositUnauthorized{}
}

/*VerifyChallengeDepositUnauthorized handles this case with default header values.

Unauthorized
*/
type VerifyChallengeDepositUnauthorized struct {
}

func (o *VerifyChallengeDepositUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /verification][%d] verifyChallengeDepositUnauthorized ", 401)
}

func (o *VerifyChallengeDepositUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewVerifyChallengeDepositNotFound creates a VerifyChallengeDepositNotFound with default headers values
func NewVerifyChallengeDepositNotFound() *VerifyChallengeDepositNotFound {
	return &VerifyChallengeDepositNotFound{}
}

/*VerifyChallengeDepositNotFound handles this case with default header values.

Not Found
*/
type VerifyChallengeDepositNotFound struct {
}

func (o *VerifyChallengeDepositNotFound) Error() string {
	return fmt.Sprintf("[PUT /verification][%d] verifyChallengeDepositNotFound ", 404)
}

func (o *VerifyChallengeDepositNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
