package ghidra.plugin.hues;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

// @formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "Hues",
    category = PluginCategoryNames.SUPPORT,
    shortDescription = "The Simple Color Changing Plugin",
    description = "The Simple Color Changing Plugin - by quosego <https://github.com/quosego>")
// @formatter:on

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 10, 2019
 */
public class HuesPlugin extends Plugin {
  private static final String PLUGIN_TITLE = "Hues - The Color Plugin";
  private HuesProvider provider;
  private DockingAction action;

  public HuesPlugin(PluginTool tool) {
    super(tool);
    provider = new HuesProvider(this);

    createActions();
  }

  public String getTitle() {
    return PLUGIN_TITLE;
  }

  @Override
  public void init() {
    super.init();
  }

  @Override
  protected void dispose() {
    provider.close();
  }

  // ==================================================================================================
  // Action Provider methods
  // ==================================================================================================

  private void showProvider() {
    if (provider == null) {
      provider = new HuesProvider(this);
    }
    if (provider.isVisible() == false) {
      provider.setVisible(true);
      provider.toFront();
    }
  }

  private void createActions() {
    action =
        new DockingAction("Open Hues", getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            showProvider();
          }
        };
    action.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/rainbow.png"), "View"));
    action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_H, InputEvent.CTRL_DOWN_MASK));

    action.setHelpLocation(new HelpLocation(getName(), "Hues"));
    tool.addAction(action);
  }
}
