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

// UpdateTransactionCategoryReader is a Reader for the UpdateTransactionCategory structure.
type UpdateTransactionCategoryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateTransactionCategoryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewUpdateTransactionCategoryNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateTransactionCategoryBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateTransactionCategoryUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateTransactionCategoryNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewUpdateTransactionCategoryNoContent creates a UpdateTransactionCategoryNoContent with default headers values
func NewUpdateTransactionCategoryNoContent() *UpdateTransactionCategoryNoContent {
	return &UpdateTransactionCategoryNoContent{}
}

/*UpdateTransactionCategoryNoContent handles this case with default header values.

Updated Successfully
*/
type UpdateTransactionCategoryNoContent struct {
}

func (o *UpdateTransactionCategoryNoContent) Error() string {
	return fmt.Sprintf("[PUT /transactions/categories][%d] updateTransactionCategoryNoContent ", 204)
}

func (o *UpdateTransactionCategoryNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateTransactionCategoryBadRequest creates a UpdateTransactionCategoryBadRequest with default headers values
func NewUpdateTransactionCategoryBadRequest() *UpdateTransactionCategoryBadRequest {
	return &UpdateTransactionCategoryBadRequest{}
}

/*UpdateTransactionCategoryBadRequest handles this case with default header values.

Y800 : Invalid value for categoryParam<br>Y800 : Invalid value for source<br>Y801 : Invalid length for categoryName. Min 1 and max 50 is required<br>Y803 : id required<br>Y811 : categoryName value already exists
*/
type UpdateTransactionCategoryBadRequest struct {
	Payload *models.YodleeError
}

func (o *UpdateTransactionCategoryBadRequest) Error() string {
	return fmt.Sprintf("[PUT /transactions/categories][%d] updateTransactionCategoryBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateTransactionCategoryBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *UpdateTransactionCategoryBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateTransactionCategoryUnauthorized creates a UpdateTransactionCategoryUnauthorized with default headers values
func NewUpdateTransactionCategoryUnauthorized() *UpdateTransactionCategoryUnauthorized {
	return &UpdateTransactionCategoryUnauthorized{}
}

/*UpdateTransactionCategoryUnauthorized handles this case with default header values.

Unauthorized
*/
type UpdateTransactionCategoryUnauthorized struct {
}

func (o *UpdateTransactionCategoryUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /transactions/categories][%d] updateTransactionCategoryUnauthorized ", 401)
}

func (o *UpdateTransactionCategoryUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateTransactionCategoryNotFound creates a UpdateTransactionCategoryNotFound with default headers values
func NewUpdateTransactionCategoryNotFound() *UpdateTransactionCategoryNotFound {
	return &UpdateTransactionCategoryNotFound{}
}

/*UpdateTransactionCategoryNotFound handles this case with default header values.

Not Found
*/
type UpdateTransactionCategoryNotFound struct {
}

func (o *UpdateTransactionCategoryNotFound) Error() string {
	return fmt.Sprintf("[PUT /transactions/categories][%d] updateTransactionCategoryNotFound ", 404)
}

func (o *UpdateTransactionCategoryNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
