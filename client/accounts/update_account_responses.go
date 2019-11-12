// Code generated by go-swagger; DO NOT EDIT.

package accounts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "yodlee-golang-client/models"
)

// UpdateAccountReader is a Reader for the UpdateAccount structure.
type UpdateAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewUpdateAccountNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateAccountUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateAccountNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewUpdateAccountNoContent creates a UpdateAccountNoContent with default headers values
func NewUpdateAccountNoContent() *UpdateAccountNoContent {
	return &UpdateAccountNoContent{}
}

/*UpdateAccountNoContent handles this case with default header values.

OK
*/
type UpdateAccountNoContent struct {
}

func (o *UpdateAccountNoContent) Error() string {
	return fmt.Sprintf("[PUT /accounts/{accountId}][%d] updateAccountNoContent ", 204)
}

func (o *UpdateAccountNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateAccountBadRequest creates a UpdateAccountBadRequest with default headers values
func NewUpdateAccountBadRequest() *UpdateAccountBadRequest {
	return &UpdateAccountBadRequest{}
}

/*UpdateAccountBadRequest handles this case with default header values.

Y800 : Invalid value for accountId<br>Y800 : Invalid value for updateParam
*/
type UpdateAccountBadRequest struct {
	Payload *models.YodleeError
}

func (o *UpdateAccountBadRequest) Error() string {
	return fmt.Sprintf("[PUT /accounts/{accountId}][%d] updateAccountBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateAccountBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *UpdateAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAccountUnauthorized creates a UpdateAccountUnauthorized with default headers values
func NewUpdateAccountUnauthorized() *UpdateAccountUnauthorized {
	return &UpdateAccountUnauthorized{}
}

/*UpdateAccountUnauthorized handles this case with default header values.

Unauthorized
*/
type UpdateAccountUnauthorized struct {
}

func (o *UpdateAccountUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /accounts/{accountId}][%d] updateAccountUnauthorized ", 401)
}

func (o *UpdateAccountUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateAccountNotFound creates a UpdateAccountNotFound with default headers values
func NewUpdateAccountNotFound() *UpdateAccountNotFound {
	return &UpdateAccountNotFound{}
}

/*UpdateAccountNotFound handles this case with default header values.

Not Found
*/
type UpdateAccountNotFound struct {
}

func (o *UpdateAccountNotFound) Error() string {
	return fmt.Sprintf("[PUT /accounts/{accountId}][%d] updateAccountNotFound ", 404)
}

func (o *UpdateAccountNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}