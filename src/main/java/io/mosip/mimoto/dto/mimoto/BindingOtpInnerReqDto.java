package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;

@Data
public class BindingOtpInnerReqDto {
    @NotNull
    private String individualId;
    @NotNull
    @NotEmpty
    @Schema(description = "Notifying medium in which OTP is sent", allowableValues = {"EMAIL"})
    private List<String> otpChannels;
}
