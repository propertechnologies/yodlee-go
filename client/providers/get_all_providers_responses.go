// Code generated by go-swagger; DO NOT EDIT.

package providers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// GetAllProvidersReader is a Reader for the GetAllProviders structure.
type GetAllProvidersReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAllProvidersReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAllProvidersOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAllProvidersBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAllProvidersUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAllProvidersNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetAllProvidersOK creates a GetAllProvidersOK with default headers values
func NewGetAllProvidersOK() *GetAllProvidersOK {
	return &GetAllProvidersOK{}
}

/*GetAllProvidersOK handles this case with default header values.

OK
*/
type GetAllProvidersOK struct {
	Payload *models.ProviderResponse
}

func (o *GetAllProvidersOK) Error() string {
	return fmt.Sprintf("[GET /providers][%d] getAllProvidersOK  %+v", 200, o.Payload)
}

func (o *GetAllProvidersOK) GetPayload() *models.ProviderResponse {
	return o.Payload
}

func (o *GetAllProvidersOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ProviderResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAllProvidersBadRequest creates a GetAllProvidersBadRequest with default headers values
func NewGetAllProvidersBadRequest() *GetAllProvidersBadRequest {
	return &GetAllProvidersBadRequest{}
}

/*GetAllProvidersBadRequest handles this case with default header values.

Y800 : Invalid value for priority<br>Y800 : Invalid value for providerName<br>Y801 : Invalid length for a site search. The search string must have atleast 1 character<br>Y800 : Invalid value for skip<br>Y804 : Permitted values of top between 1 - 500<br>Y821 : Dataset not supported<br>Y820 : The additionalDataSet is not supported for Get provider API
*/
type GetAllProvidersBadRequest struct {
	Payload *models.YodleeError
}

func (o *GetAllProvidersBadRequest) Error() string {
	return fmt.Sprintf("[GET /providers][%d] getAllProvidersBadRequest  %+v", 400, o.Payload)
}

func (o *GetAllProvidersBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *GetAllProvidersBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAllProvidersUnauthorized creates a GetAllProvidersUnauthorized with default headers values
func NewGetAllProvidersUnauthorized() *GetAllProvidersUnauthorized {
	return &GetAllProvidersUnauthorized{}
}

/*GetAllProvidersUnauthorized handles this case with default header values.

Unauthorized
*/
type GetAllProvidersUnauthorized struct {
}

func (o *GetAllProvidersUnauthorized) Error() string {
	return fmt.Sprintf("[GET /providers][%d] getAllProvidersUnauthorized ", 401)
}

func (o *GetAllProvidersUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetAllProvidersNotFound creates a GetAllProvidersNotFound with default headers values
func NewGetAllProvidersNotFound() *GetAllProvidersNotFound {
	return &GetAllProvidersNotFound{}
}

/*GetAllProvidersNotFound handles this case with default header values.

Not Found
*/
type GetAllProvidersNotFound struct {
}

func (o *GetAllProvidersNotFound) Error() string {
	return fmt.Sprintf("[GET /providers][%d] getAllProvidersNotFound ", 404)
}

func (o *GetAllProvidersNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
