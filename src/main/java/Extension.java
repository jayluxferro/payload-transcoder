import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("Payload Transcoder");

        ContextMenuItemsProvider contextMenu = new PayloadTranscoderContextMenu(montoyaApi);
        montoyaApi.userInterface().registerContextMenuItemsProvider(contextMenu);

        montoyaApi.logging().logToOutput("Payload Transcoder loaded");
    }
}