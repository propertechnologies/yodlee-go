// Code generated by go-swagger; DO NOT EDIT.

package user

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "yodlee-golang-client/models"
)

// GetAccessTokensReader is a Reader for the GetAccessTokens structure.
type GetAccessTokensReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAccessTokensReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAccessTokensOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAccessTokensUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAccessTokensNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetAccessTokensOK creates a GetAccessTokensOK with default headers values
func NewGetAccessTokensOK() *GetAccessTokensOK {
	return &GetAccessTokensOK{}
}

/*GetAccessTokensOK handles this case with default header values.

OK
*/
type GetAccessTokensOK struct {
	Payload *models.UserAccessTokensResponse
}

func (o *GetAccessTokensOK) Error() string {
	return fmt.Sprintf("[GET /user/accessTokens][%d] getAccessTokensOK  %+v", 200, o.Payload)
}

func (o *GetAccessTokensOK) GetPayload() *models.UserAccessTokensResponse {
	return o.Payload
}

func (o *GetAccessTokensOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserAccessTokensResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccessTokensUnauthorized creates a GetAccessTokensUnauthorized with default headers values
func NewGetAccessTokensUnauthorized() *GetAccessTokensUnauthorized {
	return &GetAccessTokensUnauthorized{}
}

/*GetAccessTokensUnauthorized handles this case with default header values.

Unauthorized
*/
type GetAccessTokensUnauthorized struct {
}

func (o *GetAccessTokensUnauthorized) Error() string {
	return fmt.Sprintf("[GET /user/accessTokens][%d] getAccessTokensUnauthorized ", 401)
}

func (o *GetAccessTokensUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetAccessTokensNotFound creates a GetAccessTokensNotFound with default headers values
func NewGetAccessTokensNotFound() *GetAccessTokensNotFound {
	return &GetAccessTokensNotFound{}
}

/*GetAccessTokensNotFound handles this case with default header values.

Not Found
*/
type GetAccessTokensNotFound struct {
}

func (o *GetAccessTokensNotFound) Error() string {
	return fmt.Sprintf("[GET /user/accessTokens][%d] getAccessTokensNotFound ", 404)
}

func (o *GetAccessTokensNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}