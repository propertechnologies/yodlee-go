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

// GetTransactionCategorizationRulesReader is a Reader for the GetTransactionCategorizationRules structure.
type GetTransactionCategorizationRulesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetTransactionCategorizationRulesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetTransactionCategorizationRulesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetTransactionCategorizationRulesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetTransactionCategorizationRulesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetTransactionCategorizationRulesOK creates a GetTransactionCategorizationRulesOK with default headers values
func NewGetTransactionCategorizationRulesOK() *GetTransactionCategorizationRulesOK {
	return &GetTransactionCategorizationRulesOK{}
}

/*GetTransactionCategorizationRulesOK handles this case with default header values.

OK
*/
type GetTransactionCategorizationRulesOK struct {
	Payload *models.TransactionCategorizationRuleResponse
}

func (o *GetTransactionCategorizationRulesOK) Error() string {
	return fmt.Sprintf("[GET /transactions/categories/txnRules][%d] getTransactionCategorizationRulesOK  %+v", 200, o.Payload)
}

func (o *GetTransactionCategorizationRulesOK) GetPayload() *models.TransactionCategorizationRuleResponse {
	return o.Payload
}

func (o *GetTransactionCategorizationRulesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TransactionCategorizationRuleResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTransactionCategorizationRulesUnauthorized creates a GetTransactionCategorizationRulesUnauthorized with default headers values
func NewGetTransactionCategorizationRulesUnauthorized() *GetTransactionCategorizationRulesUnauthorized {
	return &GetTransactionCategorizationRulesUnauthorized{}
}

/*GetTransactionCategorizationRulesUnauthorized handles this case with default header values.

Unauthorized
*/
type GetTransactionCategorizationRulesUnauthorized struct {
}

func (o *GetTransactionCategorizationRulesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /transactions/categories/txnRules][%d] getTransactionCategorizationRulesUnauthorized ", 401)
}

func (o *GetTransactionCategorizationRulesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetTransactionCategorizationRulesNotFound creates a GetTransactionCategorizationRulesNotFound with default headers values
func NewGetTransactionCategorizationRulesNotFound() *GetTransactionCategorizationRulesNotFound {
	return &GetTransactionCategorizationRulesNotFound{}
}

/*GetTransactionCategorizationRulesNotFound handles this case with default header values.

Not Found
*/
type GetTransactionCategorizationRulesNotFound struct {
}

func (o *GetTransactionCategorizationRulesNotFound) Error() string {
	return fmt.Sprintf("[GET /transactions/categories/txnRules][%d] getTransactionCategorizationRulesNotFound ", 404)
}

func (o *GetTransactionCategorizationRulesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
