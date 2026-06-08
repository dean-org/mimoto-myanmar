package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.DataShareResponseDto;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.datashare.DataShareResponseWrapperDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.util.RestApiClient;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.oro.text.regex.PatternMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.PathMatcher;

import java.net.URL;

@Slf4j
@Service
public class DataShareServiceImpl {

    @Autowired
    RestApiClient restApiClient;

    @Value("${mosip.data.share.url}")
    String dataShareHostUrl;

    @Value("${mosip.data.share.create.url}")
    String dataShareCreateUrl;

    @Value("${mosip.data.share.get.url.pattern}")
    String dataShareGetUrlPattern;

    @Value("${mosip.data.share.create.retry.count}")
    Integer maxRetryCount;

    @Autowired
    ObjectMapper objectMapper;

    PathMatcher pathMatcher ;

    @PostConstruct
    public void setUp(){
        pathMatcher = new AntPathMatcher();
    }

    public String storeDataInDataShare(String data, String credentialValidity) throws Exception {
        ByteArrayResource contentsAsResource = new ByteArrayResource(data.getBytes()) {
            @Override
            public String getFilename() {
                return "credential_file";
            }
        };
        LinkedMultiValueMap<String, Object> map = new LinkedMultiValueMap<>();
        map.add("file", contentsAsResource);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        HttpEntity<LinkedMultiValueMap<String, Object>> requestEntity = new HttpEntity<>(map, headers);
        DataShareResponseWrapperDTO dataShareResponseWrapperDTO = pushCredentialIntoDataShare(requestEntity, credentialValidity);
        log.info("Data pushed into DataShare -> " + dataShareResponseWrapperDTO);
        return  dataShareResponseWrapperDTO.getDataShare().getUrl();
    }

    private DataShareResponseWrapperDTO pushCredentialIntoDataShare(HttpEntity<LinkedMultiValueMap<String, Object>> requestEntity, String credentialValidity) throws Exception {
        int attempt =0 ;
        DataShareResponseWrapperDTO dataShareResponseWrapperDTO = null;
        while(attempt++ < maxRetryCount ){
            try {
                dataShareResponseWrapperDTO = restApiClient.postApi(dataShareCreateUrl + "?usageCountForStandaloneMode=" + credentialValidity, MediaType.MULTIPART_FORM_DATA, requestEntity, DataShareResponseWrapperDTO.class);
            } catch (Exception e) {
                log.error(attempt + " attempt to push credential failed");
            }
        }
        if(dataShareResponseWrapperDTO == null){
            throw new InvalidCredentialResourceException(
                    ErrorConstants.REQUEST_TIMED_OUT.getErrorCode(),
                    ErrorConstants.REQUEST_TIMED_OUT.getErrorMessage());
        }
        return dataShareResponseWrapperDTO;
    }

    public  VCCredentialResponse downloadCredentialFromDataShare(PresentationRequestDTO presentationRequestDTO) throws JsonProcessingException {
        log.info("Started the Credential Download From DataShare");
        log.info("Incoming resource URI: {}", presentationRequestDTO.getResource());
        log.info("Configured URL pattern: {}", dataShareGetUrlPattern);
        String credentialsResourceUri = presentationRequestDTO.getResource();
        if(!pathMatcher.match(dataShareGetUrlPattern, credentialsResourceUri)){
            throw new InvalidCredentialResourceException(
                    ErrorConstants.RESOURCE_INVALID.getErrorCode(),
                    ErrorConstants.RESOURCE_INVALID.getErrorMessage());
        }
        log.info("Calling DataShare GET API...");
        log.info("Final resolved URI: {}", credentialsResourceUri);
        String vcCredentialResponseString = restApiClient.getApi(credentialsResourceUri, String.class);
        log.info("Raw response from DataShare: {}", vcCredentialResponseString);
        if (vcCredentialResponseString == null) {
            throw new InvalidCredentialResourceException(
                    ErrorConstants.SERVER_UNAVAILABLE.getErrorCode(),
                    ErrorConstants.SERVER_UNAVAILABLE.getErrorMessage());
        }
        log.info("Parsed response → format={}, credentialPresent={}",
        vcCredentialResponse.getFormat(),
        vcCredentialResponse.getCredential() != null);
        VCCredentialResponse vcCredentialResponse = objectMapper.readValue(vcCredentialResponseString, VCCredentialResponse.class);
        log.info("Completed Mapping the Credential to Object => " + vcCredentialResponse );
        if(vcCredentialResponse.getCredential() == null){
            log.error("Credential is NULL from DataShare response!");
            log.error("Raw response was: {}", vcCredentialResponseString);
            DataShareResponseDto dataShareResponse = objectMapper.readValue(vcCredentialResponseString, DataShareResponseDto.class);
            log.error("Parsed DataShare error response: {}", dataShareResponse);
            log.error("ErrorCode from DataShare: {}", dataShareResponse.getErrors().get(0).getErrorCode());
            String errorCode = dataShareResponse.getErrors().get(0).getErrorCode();
            throw new InvalidCredentialResourceException(errorCode.equals("DAT-SER-008") ? ErrorConstants.RESOURCE_NOT_FOUND.getErrorMessage() : ErrorConstants.RESOURCE_EXPIRED.getErrorMessage());
        }
        return vcCredentialResponse;
    }

}
