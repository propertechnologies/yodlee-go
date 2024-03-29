// Code generated by go-swagger; DO NOT EDIT.

package provider_accounts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// GetProviderAccountReader is a Reader for the GetProviderAccount structure.
type GetProviderAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetProviderAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetProviderAccountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetProviderAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetProviderAccountUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetProviderAccountNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetProviderAccountOK creates a GetProviderAccountOK with default headers values
func NewGetProviderAccountOK() *GetProviderAccountOK {
	return &GetProviderAccountOK{}
}

/*GetProviderAccountOK handles this case with default header values.

OK
*/
type GetProviderAccountOK struct {
	Payload *models.ProviderAccountDetailResponse
}

func (o *GetProviderAccountOK) Error() string {
	return fmt.Sprintf("[GET /providerAccounts/{providerAccountId}][%d] getProviderAccountOK  %+v", 200, o.Payload)
}

func (o *GetProviderAccountOK) GetPayload() *models.ProviderAccountDetailResponse {
	return o.Payload
}

func (o *GetProviderAccountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ProviderAccountDetailResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetProviderAccountBadRequest creates a GetProviderAccountBadRequest with default headers values
func NewGetProviderAccountBadRequest() *GetProviderAccountBadRequest {
	return &GetProviderAccountBadRequest{}
}

/*GetProviderAccountBadRequest handles this case with default header values.

Y800 : Invalid value for providerAccountId<br>Y816 : questions can only be requested for questionAndAnswer Supported Sites
*/
type GetProviderAccountBadRequest struct {
	Payload *models.YodleeError
}

func (o *GetProviderAccountBadRequest) Error() string {
	return fmt.Sprintf("[GET /providerAccounts/{providerAccountId}][%d] getProviderAccountBadRequest  %+v", 400, o.Payload)
}

func (o *GetProviderAccountBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *GetProviderAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetProviderAccountUnauthorized creates a GetProviderAccountUnauthorized with default headers values
func NewGetProviderAccountUnauthorized() *GetProviderAccountUnauthorized {
	return &GetProviderAccountUnauthorized{}
}

/*GetProviderAccountUnauthorized handles this case with default header values.

Unauthorized
*/
type GetProviderAccountUnauthorized struct {
}

func (o *GetProviderAccountUnauthorized) Error() string {
	return fmt.Sprintf("[GET /providerAccounts/{providerAccountId}][%d] getProviderAccountUnauthorized ", 401)
}

func (o *GetProviderAccountUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetProviderAccountNotFound creates a GetProviderAccountNotFound with default headers values
func NewGetProviderAccountNotFound() *GetProviderAccountNotFound {
	return &GetProviderAccountNotFound{}
}

/*GetProviderAccountNotFound handles this case with default header values.

Not Found
*/
type GetProviderAccountNotFound struct {
}

func (o *GetProviderAccountNotFound) Error() string {
	return fmt.Sprintf("[GET /providerAccounts/{providerAccountId}][%d] getProviderAccountNotFound ", 404)
}

func (o *GetProviderAccountNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
