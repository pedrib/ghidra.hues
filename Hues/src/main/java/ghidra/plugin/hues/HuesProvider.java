package ghidra.plugin.hues;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.Tool;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.event.MouseEvent;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 10, 2019
 */
public class HuesProvider extends ComponentProvider {
  private HuesPlugin plugin;

  private HuesPanel panelHues;

  public HuesProvider(HuesPlugin plugin) {
    super(plugin.getTool(), plugin.getTitle(), plugin.getName());
    this.plugin = plugin;

    build();
  }

  private void build() {
    this.panelHues = new HuesPanel();
    setIcon(ResourceManager.loadImage("images/rainbow.png"));
    setWindowMenuGroup("Hues");
    setDefaultWindowPosition(WindowPosition.RIGHT);
    setHelpLocation(new HelpLocation(plugin.getName(), "Hues"));
    addToTool();
  }

  public void close() {
    this.panelHues.close();
    setVisible(false);
  }

  // ==================================================================================================
  // Component Provider methods
  // ==================================================================================================

  @Override
  public JComponent getComponent() {
    return this.panelHues.getHuesPanel();
  }

  @Override
  protected void initializeInstanceID(long newID) {
    super.initializeInstanceID(newID);
  }

  @Override
  public void requestFocus() {
    super.requestFocus();
  }

  @Override
  public void addToTool() {
    super.addToTool();
  }

  @Override
  public void removeFromTool() {
    super.removeFromTool();
  }

  @Override
  public void addLocalAction(DockingActionIf action) {
    super.addLocalAction(action);
  }

  @Override
  public void removeLocalAction(DockingAction action) {
    super.removeLocalAction(action);
  }

  @Override
  public void setVisible(boolean visible) {
    super.setVisible(visible);
  }

  @Override
  public void toFront() {
    super.toFront();
  }

  @Override
  public boolean isInTool() {
    return super.isInTool();
  }

  @Override
  public Class<?> getContextType() {
    return super.getContextType();
  }

  @Override
  public boolean isVisible() {
    return super.isVisible();
  }

  @Override
  public boolean isActive() {
    return super.isActive();
  }

  @Override
  public void closeComponent() {
    super.closeComponent();
  }

  @Override
  public void componentActivated() {
    super.componentActivated();
  }

  @Override
  public void componentDeactived() {
    super.componentDeactived();
  }

  @Override
  public void componentHidden() {
    super.componentHidden();
  }

  @Override
  public void componentShown() {
    super.componentShown();
  }

  @Override
  public ActionContext getActionContext(MouseEvent event) {
    return super.getActionContext(event);
  }

  @Override
  public void contextChanged() {
    super.contextChanged();
  }

  @Override
  public HelpLocation getHelpLocation() {
    return super.getHelpLocation();
  }

  @Override
  public void setHelpLocation(HelpLocation helpLocation) {
    super.setHelpLocation(helpLocation);
  }

  @Override
  public Icon getIcon() {
    return super.getIcon();
  }

  @Override
  public String getName() {
    return super.getName();
  }

  @Override
  public String getOwner() {
    return super.getOwner();
  }

  @Override
  public void setTitle(String title) {
    super.setTitle(title);
  }

  @Override
  public void setSubTitle(String subTitle) {
    super.setSubTitle(subTitle);
  }

  @Override
  public void setTabText(String tabText) {
    super.setTabText(tabText);
  }

  @Override
  public String getTitle() {
    return super.getTitle();
  }

  @Override
  public String getSubTitle() {
    return super.getSubTitle();
  }

  @Override
  public String getTabText() {
    return super.getTabText();
  }

  @Override
  public void setIcon(Icon icon) {
    super.setIcon(icon);
  }

  @Override
  public String getWindowSubMenuName() {
    return super.getWindowSubMenuName();
  }

  @Override
  public boolean isTransient() {
    return super.isTransient();
  }

  @Override
  protected void setTransient() {
    super.setTransient();
  }

  @Override
  protected void setWindowMenuGroup(String group) {
    super.setWindowMenuGroup(group);
  }

  @Override
  public WindowPosition getDefaultWindowPosition() {
    return super.getDefaultWindowPosition();
  }

  @Override
  protected void setDefaultWindowPosition(WindowPosition windowPosition) {
    super.setDefaultWindowPosition(windowPosition);
  }

  @Override
  public WindowPosition getIntraGroupPosition() {
    return super.getIntraGroupPosition();
  }

  @Override
  public void setIntraGroupPosition(WindowPosition position) {
    super.setIntraGroupPosition(position);
  }

  @Override
  public String getWindowGroup() {
    return super.getWindowGroup();
  }

  @Override
  protected void setWindowGroup(String group) {
    super.setWindowGroup(group);
  }

  @Override
  public String getHelpInfo() {
    return super.getHelpInfo();
  }

  @Override
  public Object getHelpObject() {
    return super.getHelpObject();
  }

  @Override
  public Tool getTool() {
    return super.getTool();
  }

  @Override
  public String toString() {
    return super.toString();
  }
}
