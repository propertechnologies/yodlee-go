// Code generated by go-swagger; DO NOT EDIT.

package cobrand

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// GetPublicKeyReader is a Reader for the GetPublicKey structure.
type GetPublicKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPublicKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPublicKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetPublicKeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetPublicKeyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetPublicKeyOK creates a GetPublicKeyOK with default headers values
func NewGetPublicKeyOK() *GetPublicKeyOK {
	return &GetPublicKeyOK{}
}

/*GetPublicKeyOK handles this case with default header values.

OK
*/
type GetPublicKeyOK struct {
	Payload *models.CobrandPublicKeyResponse
}

func (o *GetPublicKeyOK) Error() string {
	return fmt.Sprintf("[GET /cobrand/publicKey][%d] getPublicKeyOK  %+v", 200, o.Payload)
}

func (o *GetPublicKeyOK) GetPayload() *models.CobrandPublicKeyResponse {
	return o.Payload
}

func (o *GetPublicKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CobrandPublicKeyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPublicKeyUnauthorized creates a GetPublicKeyUnauthorized with default headers values
func NewGetPublicKeyUnauthorized() *GetPublicKeyUnauthorized {
	return &GetPublicKeyUnauthorized{}
}

/*GetPublicKeyUnauthorized handles this case with default header values.

Unauthorized
*/
type GetPublicKeyUnauthorized struct {
}

func (o *GetPublicKeyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /cobrand/publicKey][%d] getPublicKeyUnauthorized ", 401)
}

func (o *GetPublicKeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetPublicKeyNotFound creates a GetPublicKeyNotFound with default headers values
func NewGetPublicKeyNotFound() *GetPublicKeyNotFound {
	return &GetPublicKeyNotFound{}
}

/*GetPublicKeyNotFound handles this case with default header values.

Not Found
*/
type GetPublicKeyNotFound struct {
}

func (o *GetPublicKeyNotFound) Error() string {
	return fmt.Sprintf("[GET /cobrand/publicKey][%d] getPublicKeyNotFound ", 404)
}

func (o *GetPublicKeyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
