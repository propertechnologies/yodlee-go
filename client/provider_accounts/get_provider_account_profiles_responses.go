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

// GetProviderAccountProfilesReader is a Reader for the GetProviderAccountProfiles structure.
type GetProviderAccountProfilesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetProviderAccountProfilesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetProviderAccountProfilesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetProviderAccountProfilesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetProviderAccountProfilesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetProviderAccountProfilesOK creates a GetProviderAccountProfilesOK with default headers values
func NewGetProviderAccountProfilesOK() *GetProviderAccountProfilesOK {
	return &GetProviderAccountProfilesOK{}
}

/*GetProviderAccountProfilesOK handles this case with default header values.

OK
*/
type GetProviderAccountProfilesOK struct {
	Payload *models.ProviderAccountUserProfileResponse
}

func (o *GetProviderAccountProfilesOK) Error() string {
	return fmt.Sprintf("[GET /providerAccounts/profile][%d] getProviderAccountProfilesOK  %+v", 200, o.Payload)
}

func (o *GetProviderAccountProfilesOK) GetPayload() *models.ProviderAccountUserProfileResponse {
	return o.Payload
}

func (o *GetProviderAccountProfilesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ProviderAccountUserProfileResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetProviderAccountProfilesUnauthorized creates a GetProviderAccountProfilesUnauthorized with default headers values
func NewGetProviderAccountProfilesUnauthorized() *GetProviderAccountProfilesUnauthorized {
	return &GetProviderAccountProfilesUnauthorized{}
}

/*GetProviderAccountProfilesUnauthorized handles this case with default header values.

Unauthorized
*/
type GetProviderAccountProfilesUnauthorized struct {
}

func (o *GetProviderAccountProfilesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /providerAccounts/profile][%d] getProviderAccountProfilesUnauthorized ", 401)
}

func (o *GetProviderAccountProfilesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetProviderAccountProfilesNotFound creates a GetProviderAccountProfilesNotFound with default headers values
func NewGetProviderAccountProfilesNotFound() *GetProviderAccountProfilesNotFound {
	return &GetProviderAccountProfilesNotFound{}
}

/*GetProviderAccountProfilesNotFound handles this case with default header values.

Not Found
*/
type GetProviderAccountProfilesNotFound struct {
}

func (o *GetProviderAccountProfilesNotFound) Error() string {
	return fmt.Sprintf("[GET /providerAccounts/profile][%d] getProviderAccountProfilesNotFound ", 404)
}

func (o *GetProviderAccountProfilesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
