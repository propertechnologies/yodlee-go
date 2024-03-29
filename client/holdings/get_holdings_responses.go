// Code generated by go-swagger; DO NOT EDIT.

package holdings

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// GetHoldingsReader is a Reader for the GetHoldings structure.
type GetHoldingsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetHoldingsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetHoldingsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetHoldingsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetHoldingsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetHoldingsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetHoldingsOK creates a GetHoldingsOK with default headers values
func NewGetHoldingsOK() *GetHoldingsOK {
	return &GetHoldingsOK{}
}

/*GetHoldingsOK handles this case with default header values.

OK
*/
type GetHoldingsOK struct {
	Payload *models.HoldingResponse
}

func (o *GetHoldingsOK) Error() string {
	return fmt.Sprintf("[GET /holdings][%d] getHoldingsOK  %+v", 200, o.Payload)
}

func (o *GetHoldingsOK) GetPayload() *models.HoldingResponse {
	return o.Payload
}

func (o *GetHoldingsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.HoldingResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetHoldingsBadRequest creates a GetHoldingsBadRequest with default headers values
func NewGetHoldingsBadRequest() *GetHoldingsBadRequest {
	return &GetHoldingsBadRequest{}
}

/*GetHoldingsBadRequest handles this case with default header values.

Y800 : Invalid value for accountId<br>Y800 : Invalid value for providerAccountId<br>Y800 : Invalid value for include<br>Y800 : Invalid value for classificationType<br>Y800 : Invalid value for classificationValue<br>Y800 : Invalid value for include<br>Y400 : classificationType mismatch<br>Y400 : classificationValue mismatch<br>Y824 : The maximum number of accountIds permitted is 100
*/
type GetHoldingsBadRequest struct {
	Payload *models.YodleeError
}

func (o *GetHoldingsBadRequest) Error() string {
	return fmt.Sprintf("[GET /holdings][%d] getHoldingsBadRequest  %+v", 400, o.Payload)
}

func (o *GetHoldingsBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *GetHoldingsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetHoldingsUnauthorized creates a GetHoldingsUnauthorized with default headers values
func NewGetHoldingsUnauthorized() *GetHoldingsUnauthorized {
	return &GetHoldingsUnauthorized{}
}

/*GetHoldingsUnauthorized handles this case with default header values.

Unauthorized
*/
type GetHoldingsUnauthorized struct {
}

func (o *GetHoldingsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /holdings][%d] getHoldingsUnauthorized ", 401)
}

func (o *GetHoldingsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetHoldingsNotFound creates a GetHoldingsNotFound with default headers values
func NewGetHoldingsNotFound() *GetHoldingsNotFound {
	return &GetHoldingsNotFound{}
}

/*GetHoldingsNotFound handles this case with default header values.

Not Found
*/
type GetHoldingsNotFound struct {
}

func (o *GetHoldingsNotFound) Error() string {
	return fmt.Sprintf("[GET /holdings][%d] getHoldingsNotFound ", 404)
}

func (o *GetHoldingsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
