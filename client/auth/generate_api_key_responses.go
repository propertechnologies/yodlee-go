// Code generated by go-swagger; DO NOT EDIT.

package auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// GenerateAPIKeyReader is a Reader for the GenerateAPIKey structure.
type GenerateAPIKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GenerateAPIKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewGenerateAPIKeyCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGenerateAPIKeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGenerateAPIKeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGenerateAPIKeyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGenerateAPIKeyCreated creates a GenerateAPIKeyCreated with default headers values
func NewGenerateAPIKeyCreated() *GenerateAPIKeyCreated {
	return &GenerateAPIKeyCreated{}
}

/*GenerateAPIKeyCreated handles this case with default header values.

OK
*/
type GenerateAPIKeyCreated struct {
	Payload *models.APIKeyResponse
}

func (o *GenerateAPIKeyCreated) Error() string {
	return fmt.Sprintf("[POST /auth/apiKey][%d] generateApiKeyCreated  %+v", 201, o.Payload)
}

func (o *GenerateAPIKeyCreated) GetPayload() *models.APIKeyResponse {
	return o.Payload
}

func (o *GenerateAPIKeyCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIKeyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateAPIKeyBadRequest creates a GenerateAPIKeyBadRequest with default headers values
func NewGenerateAPIKeyBadRequest() *GenerateAPIKeyBadRequest {
	return &GenerateAPIKeyBadRequest{}
}

/*GenerateAPIKeyBadRequest handles this case with default header values.

Y800 : Invalid value for RS512 publicKey<br>Y806 : Invalid input<br>Y824 : The maximum number of apiKey permitted is 5<br>Y811 : publicKey value already exists
*/
type GenerateAPIKeyBadRequest struct {
	Payload *models.YodleeError
}

func (o *GenerateAPIKeyBadRequest) Error() string {
	return fmt.Sprintf("[POST /auth/apiKey][%d] generateApiKeyBadRequest  %+v", 400, o.Payload)
}

func (o *GenerateAPIKeyBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *GenerateAPIKeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateAPIKeyUnauthorized creates a GenerateAPIKeyUnauthorized with default headers values
func NewGenerateAPIKeyUnauthorized() *GenerateAPIKeyUnauthorized {
	return &GenerateAPIKeyUnauthorized{}
}

/*GenerateAPIKeyUnauthorized handles this case with default header values.

Unauthorized
*/
type GenerateAPIKeyUnauthorized struct {
}

func (o *GenerateAPIKeyUnauthorized) Error() string {
	return fmt.Sprintf("[POST /auth/apiKey][%d] generateApiKeyUnauthorized ", 401)
}

func (o *GenerateAPIKeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGenerateAPIKeyNotFound creates a GenerateAPIKeyNotFound with default headers values
func NewGenerateAPIKeyNotFound() *GenerateAPIKeyNotFound {
	return &GenerateAPIKeyNotFound{}
}

/*GenerateAPIKeyNotFound handles this case with default header values.

Not Found
*/
type GenerateAPIKeyNotFound struct {
}

func (o *GenerateAPIKeyNotFound) Error() string {
	return fmt.Sprintf("[POST /auth/apiKey][%d] generateApiKeyNotFound ", 404)
}

func (o *GenerateAPIKeyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
