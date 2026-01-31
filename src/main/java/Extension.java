import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.menu.BasicMenuItem;
import burp.api.montoya.ui.menu.Menu;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("Payload Transcoder");

        PayloadTranscoderTab transcoderTab = new PayloadTranscoderTab(montoyaApi);
        ContextMenuItemsProvider contextMenu = new PayloadTranscoderContextMenu(montoyaApi, transcoderTab);
        montoyaApi.userInterface().registerContextMenuItemsProvider(contextMenu);

        montoyaApi.userInterface().registerSuiteTab("Payload Transcoder", transcoderTab);

        for (var processor : PayloadTranscoderIntruderProcessors.createProcessors(montoyaApi)) {
            montoyaApi.intruder().registerPayloadProcessor(processor);
        }

        BasicMenuItem openTabItem = BasicMenuItem.basicMenuItem("Open Payload Transcoder")
                .withAction(transcoderTab::requestFocusInWindow);
        Menu transcoderMenu = Menu.menu("Payload Transcoder").withMenuItems(openTabItem);
        montoyaApi.userInterface().menuBar().registerMenu(transcoderMenu);

        montoyaApi.logging().logToOutput("Payload Transcoder loaded");
    }
}