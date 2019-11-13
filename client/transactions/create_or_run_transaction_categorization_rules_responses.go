// Code generated by go-swagger; DO NOT EDIT.

package transactions

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// CreateOrRunTransactionCategorizationRulesReader is a Reader for the CreateOrRunTransactionCategorizationRules structure.
type CreateOrRunTransactionCategorizationRulesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateOrRunTransactionCategorizationRulesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateOrRunTransactionCategorizationRulesCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewCreateOrRunTransactionCategorizationRulesNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateOrRunTransactionCategorizationRulesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateOrRunTransactionCategorizationRulesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateOrRunTransactionCategorizationRulesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewCreateOrRunTransactionCategorizationRulesCreated creates a CreateOrRunTransactionCategorizationRulesCreated with default headers values
func NewCreateOrRunTransactionCategorizationRulesCreated() *CreateOrRunTransactionCategorizationRulesCreated {
	return &CreateOrRunTransactionCategorizationRulesCreated{}
}

/*CreateOrRunTransactionCategorizationRulesCreated handles this case with default header values.

Created Successfully
*/
type CreateOrRunTransactionCategorizationRulesCreated struct {
}

func (o *CreateOrRunTransactionCategorizationRulesCreated) Error() string {
	return fmt.Sprintf("[POST /transactions/categories/rules][%d] createOrRunTransactionCategorizationRulesCreated ", 201)
}

func (o *CreateOrRunTransactionCategorizationRulesCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCreateOrRunTransactionCategorizationRulesNoContent creates a CreateOrRunTransactionCategorizationRulesNoContent with default headers values
func NewCreateOrRunTransactionCategorizationRulesNoContent() *CreateOrRunTransactionCategorizationRulesNoContent {
	return &CreateOrRunTransactionCategorizationRulesNoContent{}
}

/*CreateOrRunTransactionCategorizationRulesNoContent handles this case with default header values.

No Content
*/
type CreateOrRunTransactionCategorizationRulesNoContent struct {
}

func (o *CreateOrRunTransactionCategorizationRulesNoContent) Error() string {
	return fmt.Sprintf("[POST /transactions/categories/rules][%d] createOrRunTransactionCategorizationRulesNoContent ", 204)
}

func (o *CreateOrRunTransactionCategorizationRulesNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCreateOrRunTransactionCategorizationRulesBadRequest creates a CreateOrRunTransactionCategorizationRulesBadRequest with default headers values
func NewCreateOrRunTransactionCategorizationRulesBadRequest() *CreateOrRunTransactionCategorizationRulesBadRequest {
	return &CreateOrRunTransactionCategorizationRulesBadRequest{}
}

/*CreateOrRunTransactionCategorizationRulesBadRequest handles this case with default header values.

Y806 : Invalid input<br>Y400 : Rule already exists. Rule should be unique in terms of combination of description and amount
*/
type CreateOrRunTransactionCategorizationRulesBadRequest struct {
	Payload *models.YodleeError
}

func (o *CreateOrRunTransactionCategorizationRulesBadRequest) Error() string {
	return fmt.Sprintf("[POST /transactions/categories/rules][%d] createOrRunTransactionCategorizationRulesBadRequest  %+v", 400, o.Payload)
}

func (o *CreateOrRunTransactionCategorizationRulesBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *CreateOrRunTransactionCategorizationRulesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOrRunTransactionCategorizationRulesUnauthorized creates a CreateOrRunTransactionCategorizationRulesUnauthorized with default headers values
func NewCreateOrRunTransactionCategorizationRulesUnauthorized() *CreateOrRunTransactionCategorizationRulesUnauthorized {
	return &CreateOrRunTransactionCategorizationRulesUnauthorized{}
}

/*CreateOrRunTransactionCategorizationRulesUnauthorized handles this case with default header values.

Unauthorized
*/
type CreateOrRunTransactionCategorizationRulesUnauthorized struct {
}

func (o *CreateOrRunTransactionCategorizationRulesUnauthorized) Error() string {
	return fmt.Sprintf("[POST /transactions/categories/rules][%d] createOrRunTransactionCategorizationRulesUnauthorized ", 401)
}

func (o *CreateOrRunTransactionCategorizationRulesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCreateOrRunTransactionCategorizationRulesNotFound creates a CreateOrRunTransactionCategorizationRulesNotFound with default headers values
func NewCreateOrRunTransactionCategorizationRulesNotFound() *CreateOrRunTransactionCategorizationRulesNotFound {
	return &CreateOrRunTransactionCategorizationRulesNotFound{}
}

/*CreateOrRunTransactionCategorizationRulesNotFound handles this case with default header values.

Not Found
*/
type CreateOrRunTransactionCategorizationRulesNotFound struct {
}

func (o *CreateOrRunTransactionCategorizationRulesNotFound) Error() string {
	return fmt.Sprintf("[POST /transactions/categories/rules][%d] createOrRunTransactionCategorizationRulesNotFound ", 404)
}

func (o *CreateOrRunTransactionCategorizationRulesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
