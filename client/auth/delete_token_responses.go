// Code generated by go-swagger; DO NOT EDIT.

package auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "yodlee-golang-client/models"
)

// DeleteTokenReader is a Reader for the DeleteToken structure.
type DeleteTokenReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteTokenReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteTokenNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteTokenUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteTokenNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeleteTokenNoContent creates a DeleteTokenNoContent with default headers values
func NewDeleteTokenNoContent() *DeleteTokenNoContent {
	return &DeleteTokenNoContent{}
}

/*DeleteTokenNoContent handles this case with default header values.

No Content
*/
type DeleteTokenNoContent struct {
}

func (o *DeleteTokenNoContent) Error() string {
	return fmt.Sprintf("[DELETE /auth/token][%d] deleteTokenNoContent ", 204)
}

func (o *DeleteTokenNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteTokenUnauthorized creates a DeleteTokenUnauthorized with default headers values
func NewDeleteTokenUnauthorized() *DeleteTokenUnauthorized {
	return &DeleteTokenUnauthorized{}
}

/*DeleteTokenUnauthorized handles this case with default header values.

Y020 : Invalid token in authorization header<br>Y023 : Token has expired
*/
type DeleteTokenUnauthorized struct {
	Payload *models.YodleeError
}

func (o *DeleteTokenUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /auth/token][%d] deleteTokenUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteTokenUnauthorized) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *DeleteTokenUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTokenNotFound creates a DeleteTokenNotFound with default headers values
func NewDeleteTokenNotFound() *DeleteTokenNotFound {
	return &DeleteTokenNotFound{}
}

/*DeleteTokenNotFound handles this case with default header values.

Not Found
*/
type DeleteTokenNotFound struct {
}

func (o *DeleteTokenNotFound) Error() string {
	return fmt.Sprintf("[DELETE /auth/token][%d] deleteTokenNotFound ", 404)
}

func (o *DeleteTokenNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}